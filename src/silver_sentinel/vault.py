"""加密证据仓：把「证据」变成可携带、可校验、可多端合并的数据。

要解决的问题
------------
1. **原始文件不能裸奔**。截图、HTML、APK 里可能含受害者信息，也可能含采集端信息。
   统一 AES-256-GCM 加密后再落盘/上云，密钥只在持有者手里。
2. **证据要能被第三方复核**。仓库侧只放 SHA-256、逐条哈希链、保管链记录——
   这些是「固定证据」，体积小、可公开、可进 Git。
3. **换一台机器要能把历史全带走**。拉取时先读账本，再按 SHA-256 取密文、
   解密、校验、重建数据库行。新节点因此天然拥有全部历史。
4. **多人/多设备要能合并**。每个节点写自己的账本文件，不做共享文件的并发写；
   合并时按内容哈希去重。这样云盘、S3、IPFS 都不会产生写冲突。

目录布局（data 目录下）
----------------------
    vault.key                     32 字节主密钥（0600，绝不上传）
    vault_node.json               节点标识
    vault.lock                    跨进程锁
    vault/blobs/ab/abcd….ssv      本地加密副本（内容寻址）
    ledger/<node>.jsonl           本节点账本（哈希链）
    ledger/custody-<node>.jsonl   保管链（谁在何时对哪份证据做了什么）
    ledger/remote/<node>.jsonl    其他节点的账本副本（只读）

对外只暴露三件事：push（固化并上传）、pull（拉取并重建）、verify（复核）。
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import logging
import os
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import session_scope
from .domain import utcnow
from .models import TIER_CANDIDATE, Asset, Evidence

log = logging.getLogger(__name__)

MAGIC = b"SSV1"
NONCE_LEN = 12
KEY_LEN = 32
GENESIS = "0" * 64


class VaultError(RuntimeError):
    pass


class VaultLocked(VaultError):
    pass


# ---------------------------------------------------------------- 编解码


def canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def _open_with_length(blob: bytes, key: bytes, sha256: str) -> bytes:
    """密文布局：MAGIC | nonce | 4字节明文长度 | ciphertext。

    把长度放在 GCM 之外是为了构造成 AAD；长度本身被 GCM 保护，
    因为 AAD 参与认证——改了长度，解密直接失败。
    """
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_LEN + 4:
        raise VaultError("密文格式不正确")
    nonce = blob[len(MAGIC): len(MAGIC) + NONCE_LEN]
    size = int.from_bytes(blob[len(MAGIC) + NONCE_LEN: len(MAGIC) + NONCE_LEN + 4], "big")
    ct = blob[len(MAGIC) + NONCE_LEN + 4:]
    aad = MAGIC + b"|" + sha256.encode() + b"|" + str(size).encode()
    try:
        data = AESGCM(key).decrypt(nonce, ct, aad)
    except Exception as exc:  # noqa: BLE001
        raise VaultError("密文校验失败（密钥不匹配或文件损坏）") from exc
    if len(data) != size:
        raise VaultError("明文长度与头部不一致")
    return data


def _seal_with_length(data: bytes, key: bytes, sha256: str) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    aad = MAGIC + b"|" + sha256.encode() + b"|" + str(len(data)).encode()
    ct = AESGCM(key).encrypt(nonce, data, aad)
    return MAGIC + nonce + len(data).to_bytes(4, "big") + ct


# ---------------------------------------------------------------- 密钥


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


class Keyring:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or settings.vault_key_file or (settings.data_dir / "vault.key"))
        self._key: bytes | None = None

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.key).hexdigest()[:16]

    @property
    def key(self) -> bytes:
        if self._key is None:
            self._key = self._load()
        return self._key

    def _load(self) -> bytes:
        if settings.vault_key:
            raw = _b64d(settings.vault_key.strip())
            if len(raw) != KEY_LEN:
                raise VaultError("SILVER_VAULT_KEY 必须是 32 字节的 base64")
            return raw
        if self.path.is_file():
            raw = _b64d(self.path.read_text(encoding="utf-8").strip())
            if len(raw) != KEY_LEN:
                raise VaultError(f"密钥文件长度不正确：{self.path}")
            return raw
        if settings.vault_passphrase:
            # 口令派生：盐固定为项目标识，保证多设备派生一致；口令强度由使用者负责
            salt = b"silver-sentinel-vault-v1"
            return Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(
                settings.vault_passphrase.encode("utf-8")
            )
        raise VaultLocked("未提供证据仓密钥：设置 SILVER_VAULT_KEY / SILVER_VAULT_PASSPHRASE，或先执行 vault init")

    def create(self, passphrase: str = "") -> bytes:
        if passphrase:
            salt = b"silver-sentinel-vault-v1"
            raw = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
        else:
            raw = secrets.token_bytes(KEY_LEN)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(_b64e(raw), encoding="utf-8")
        os.chmod(self.path, 0o600)
        self._key = raw
        return raw


# ---------------------------------------------------------------- 后端


class Backend:
    name = "base"

    def put(self, name: str, data: bytes) -> str:
        raise NotImplementedError

    def get(self, name: str) -> bytes | None:
        raise NotImplementedError

    def list(self, prefix: str = "") -> list[str]:
        raise NotImplementedError

    def exists(self, name: str) -> bool:
        try:
            return self.get(name) is not None
        except Exception:  # noqa: BLE001
            return False

    def size(self, name: str) -> int | None:
        """远端对象大小。用于「同名同大小就算重复」的判定，避免整份读回来。"""
        return None

    def delete(self, name: str) -> bool:
        raise NotImplementedError


class DirBackend(Backend):
    name = "dir"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def put(self, name: str, data: bytes) -> str:
        dest = self.root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        return name

    def get(self, name: str) -> bytes | None:
        path = self.root / name
        return path.read_bytes() if path.is_file() else None

    def list(self, prefix: str = "") -> list[str]:
        base = self.root / prefix
        if base.is_dir():
            return [str(p.relative_to(self.root)) for p in sorted(base.rglob("*")) if p.is_file()]
        parent = (self.root / prefix).parent
        if not parent.is_dir():
            return []
        pfx = Path(prefix).name
        return [str(p.relative_to(self.root)) for p in sorted(parent.glob(pfx + "*")) if p.is_file()]

    def size(self, name: str) -> int | None:
        path = self.root / name
        try:
            return path.stat().st_size if path.is_file() else None
        except OSError:
            return None

    def delete(self, name: str) -> bool:
        path = self.root / name
        try:
            if path.is_file():
                path.unlink()
                return True
        except OSError:
            return False
        return False


class S3Backend(Backend):
    name = "s3"

    def __init__(self) -> None:
        try:
            import boto3  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise VaultError("S3 后端需要 boto3：pip install 'silver-sentinel[s3]'") from exc
        import boto3

        self.client = boto3.client(
            "s3",
            endpoint_url=settings.vault_target or None,
            aws_access_key_id=settings.vault_access_key,
            aws_secret_access_key=settings.vault_secret_key,
            region_name="us-east-1",
        )
        self.bucket = settings.vault_bucket

    def put(self, name: str, data: bytes) -> str:
        self.client.put_object(Bucket=self.bucket, Key=name, Body=data)
        return name

    def get(self, name: str) -> bytes | None:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=name)
            return obj["Body"].read()
        except Exception:  # noqa: BLE001
            return None

    def delete(self, name: str) -> bool:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=name)
            return True
        except Exception:  # noqa: BLE001
            return False

    def list(self, prefix: str = "") -> list[str]:
        out: list[str] = []
        token = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self.bucket, "Prefix": prefix, "MaxKeys": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self.client.list_objects_v2(**kwargs)
            out.extend(item["Key"] for item in resp.get("Contents", []))
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return out


class WebDAVBackend(Backend):
    name = "webdav"

    def __init__(self) -> None:
        self.base = settings.vault_target.rstrip("/")
        self.auth = (settings.vault_access_key, settings.vault_secret_key)

    def put(self, name: str, data: bytes) -> str:
        url = f"{self.base}/{name}"
        with httpx.Client(timeout=60, auth=self.auth) as client:
            parent = url.rsplit("/", 1)[0]
            try:
                client.request("MKCOL", parent)
            except httpx.HTTPError:
                pass
            resp = client.put(url, content=data)
            if resp.status_code not in (200, 201, 204):
                raise VaultError(f"WebDAV 上传失败：{resp.status_code}")
        return name

    def get(self, name: str) -> bytes | None:
        url = f"{self.base}/{name}"
        try:
            with httpx.Client(timeout=60, auth=self.auth) as client:
                resp = client.get(url)
                return resp.content if resp.status_code == 200 else None
        except httpx.HTTPError:
            return None

    def list(self, prefix: str = "") -> list[str]:
        url = f"{self.base}/{prefix}".rstrip("/") + "/"
        body = b"""<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"""
        try:
            with httpx.Client(timeout=30, auth=self.auth) as client:
                resp = client.request("PROPFIND", url, content=body, headers={"Depth": "1"})
                if resp.status_code not in (207, 200):
                    return []
                root = ElementTree.fromstring(resp.content)
        except (httpx.HTTPError, ElementTree.ParseError):
            return []
        out: list[str] = []
        for href in root.iter("{DAV:}href"):
            text = (href.text or "").strip()
            if not text or text.endswith("/"):
                continue
            path = httpx.URL(text).path.lstrip("/")
            if "/" in path:
                # 只保留相对 base 的部分
                idx = path.find(prefix)
                path = path[idx:] if idx >= 0 else path
            if path and not path.endswith(".tmp"):
                out.append(path)
        return out


class IpfsBackend(Backend):
    """Kubo RPC。用 MFS 维持人类可读的路径，CID 天然做去重与分发。"""

    name = "ipfs"

    def __init__(self) -> None:
        self.api = (settings.vault_target or "http://127.0.0.1:5001").rstrip("/")
        self.root = "/silver-sentinel"

    def _post(self, path: str, **params: Any) -> bytes:
        query = {k: v for k, v in params.items() if v is not None}
        with httpx.Client(timeout=120) as client:
            resp = client.post(f"{self.api}{path}", params=query)
            if resp.status_code != 200:
                raise VaultError(f"IPFS {path} 失败：{resp.status_code} {resp.text[:200]}")
            return resp.content

    def _mkdir(self, path: str) -> None:
        try:
            self._post("/api/v0/files/mkdir", arg=path, parents="true")
        except VaultError:
            pass

    def put(self, name: str, data: bytes) -> str:
        with httpx.Client(timeout=180) as client:
            resp = client.post(
                f"{self.api}/api/v0/add",
                params={"pin": "true", "cid-version": "1"},
                files={"file": (Path(name).name, data)},
            )
            if resp.status_code != 200:
                raise VaultError(f"IPFS add 失败：{resp.status_code}")
            cid = json.loads(resp.text.strip().splitlines()[-1])["Hash"]

        full = f"{self.root}/{name}"
        self._mkdir(str(Path(full).parent))
        try:
            self._post("/api/v0/files/rm", arg=full, force="true")
        except VaultError:
            pass
        self._post("/api/v0/files/cp", arg=f"/ipfs/{cid}", dest=full)
        return cid

    def get(self, name: str) -> bytes | None:
        full = f"{self.root}/{name}"
        try:
            stat = json.loads(self._post("/api/v0/files/stat", arg=full))
            cid = stat.get("Hash")
            if not cid:
                return None
            return self._post("/api/v0/cat", arg=cid)
        except (VaultError, json.JSONDecodeError):
            return None

    def list(self, prefix: str = "") -> list[str]:
        path = f"{self.root}/{prefix}".rstrip("/")
        try:
            resp = json.loads(self._post("/api/v0/files/ls", arg=path, long="true"))
        except (VaultError, json.JSONDecodeError):
            return []
        out: list[str] = []
        for item in resp.get("Entries") or []:
            name = item.get("Name")
            if not name:
                continue
            full = f"{prefix.rstrip('/')}/{name}" if prefix else name
            if item.get("Type") == 0:
                out.extend(self.list(full))
            else:
                out.append(full)
        return out


def make_backend() -> Backend:
    kind = settings.vault_backend
    if not settings.vault_target and kind in {"dir", "webdav", "ipfs"}:
        raise VaultError("未配置 SILVER_VAULT_TARGET")
    if kind == "dir":
        return DirBackend(settings.vault_target)
    if kind == "s3":
        return S3Backend()
    if kind == "webdav":
        return WebDAVBackend()
    if kind == "ipfs":
        return IpfsBackend()
    raise VaultError(f"未知的 vault 后端：{kind}")


# ---------------------------------------------------------------- 节点与状��


@dataclass
class VaultState:
    last_pull: str = ""
    last_push: str = ""
    last_error: str = ""
    pushed: int = 0
    pulled: int = 0
    pushed_bytes: int = 0
    pulled_bytes: int = 0
    remote_entries: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_pull": self.last_pull,
            "last_push": self.last_push,
            "last_error": self.last_error,
            "pushed": self.pushed,
            "pulled": self.pulled,
            "pushed_bytes": self.pushed_bytes,
            "pulled_bytes": self.pulled_bytes,
            "remote_entries": self.remote_entries,
            "history": self.history[-20:],
        }


def blob_path(sha256: str) -> Path:
    """本地密文路径。唯一权威定义，evidence 层也用它判断「文件还在不在」。"""
    return settings.data_dir / "vault" / "blobs" / sha256[:2] / f"{sha256}.ssv"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


class Vault:
    def __init__(self) -> None:
        self.keys = Keyring()
        self.node_id = self._load_node_id()
        self.state = self._load_state()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.backend: Backend | None = None
        self._backend_error = ""

    # ------------------------------------------------------ 基础
    def _load_node_id(self) -> str:
        path = settings.data_dir / "vault_node.json"
        if settings.vault_node_id:
            return settings.vault_node_id
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))["node_id"]
            except (json.JSONDecodeError, KeyError):
                pass
        node = "node-" + secrets.token_hex(4)
        _atomic_write(path, json.dumps({"node_id": node, "created_at": utcnow().isoformat()}).encode())
        return node

    def _load_state(self) -> VaultState:
        path = settings.data_dir / "vault_state.json"
        if path.is_file():
            try:
                return VaultState(**json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, TypeError):
                pass
        return VaultState()

    def _save_state(self) -> None:
        _atomic_write(
            settings.data_dir / "vault_state.json",
            json.dumps(self.state.to_dict(), ensure_ascii=False, indent=2).encode("utf-8"),
        )

    @property
    def ledger_dir(self) -> Path:
        return settings.data_dir / "ledger"

    @property
    def remote_ledger_dir(self) -> Path:
        return self.ledger_dir / "remote"

    @property
    def manifest_path(self) -> Path:
        return self.ledger_dir / f"{self.node_id}.jsonl"

    @property
    def custody_path(self) -> Path:
        return self.ledger_dir / f"custody-{self.node_id}.jsonl"

    @property
    def local_blob_dir(self) -> Path:
        return settings.data_dir / "vault" / "blobs"

    def _backend(self) -> Backend:
        if self.backend is None:
            self.backend = make_backend()
        return self.backend

    def backend_same_device(self) -> bool:
        """「远端」和本地密文在同一个文件系统上。

        这时候 push 只是把已经存在的密文原样再写一遍：盘坏了一起坏，
        既不是备份，又白占一倍空间（线上 1.6G 变 3.3G，磁盘 92%）。
        判定为真时不再复制，只记本地位置。
        """
        if settings.vault_backend != "dir" or not settings.vault_target:
            return False

        def _dev(path: Path) -> int | None:
            # 目标目录可能还没建（首次 push 之前），往上找第一个存在的祖先
            probe = path
            while True:
                try:
                    return probe.stat().st_dev
                except OSError:
                    if probe.parent == probe:
                        return None
                    probe = probe.parent

        target = Path(settings.vault_target).resolve()
        local = (settings.data_dir / "vault").resolve()
        if target == local:
            return True
        a, b = _dev(target), _dev(local)
        return a is not None and a == b

    def _file_lock(self):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        fh = open(settings.data_dir / "vault.lock", "w")
        fcntl.flock(fh, fcntl.LOCK_EX)
        return fh

    # ------------------------------------------------------ 账本读写
    def read_manifest(self, path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        out: list[dict[str, Any]] = []
        for raw in path.read_bytes().splitlines():
            if not raw.strip():
                continue
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                break
        return out

    def _append_jsonl(self, path: Path, entry: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(canonical(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _last_entry(self, path: Path) -> dict[str, Any] | None:
        entries = self.read_manifest(path)
        return entries[-1] if entries else None

    def _append_manifest(self, entry: dict[str, Any]) -> dict[str, Any]:
        last = self._last_entry(self.manifest_path)
        entry = dict(entry)
        entry["seq"] = int(last["seq"]) + 1 if last else 1
        entry["prev"] = last["hash"] if last else GENESIS
        entry["node"] = self.node_id
        entry["ts"] = utcnow().isoformat(timespec="milliseconds")
        entry["hash"] = _hash_entry(entry)
        self._append_jsonl(self.manifest_path, entry)
        return entry

    def _append_custody(self, action: str, sha256: str, **detail: Any) -> dict[str, Any]:
        last = self._last_entry(self.custody_path)
        entry = {
            "v": 1,
            "seq": int(last["seq"]) + 1 if last else 1,
            "prev": last["hash"] if last else GENESIS,
            "node": self.node_id,
            "ts": utcnow().isoformat(timespec="milliseconds"),
            "action": action,
            "subject": sha256,
            "actor": detail.pop("actor", "system"),
            "detail": detail,
        }
        entry["hash"] = _hash_entry(entry)
        self._append_jsonl(self.custody_path, entry)
        return entry

    # ------------------------------------------------------ 加密与本地副本
    def _blob_name(self, sha256: str) -> str:
        return f"blobs/{sha256[:2]}/{sha256}.ssv"

    def _local_blob_path(self, sha256: str) -> Path:
        return blob_path(sha256)

    def seal_local(self, sha256: str, data: bytes) -> bytes:
        blob = _seal_with_length(data, self.keys.key, sha256)
        _atomic_write(self._local_blob_path(sha256), blob)
        return blob

    def open_local(self, sha256: str) -> bytes | None:
        path = self._local_blob_path(sha256)
        if not path.is_file():
            return None
        data = _open_with_length(path.read_bytes(), self.keys.key, sha256)
        if hashlib.sha256(data).hexdigest() != sha256:
            raise VaultError(f"本地密文解密后哈希不符：{sha256}")
        return data

    def materialize(self, sha256: str) -> Path | None:
        """需要读原始证据时（人工复核、导出），把明文临时还原。

        落到 `tmp/` 而不是 evidence 目录：证据已经脱敏过一次，
        再写回证据目录等于让它重新裸奔在磁盘上，下一次备份又带走一份。
        """
        with session_scope() as session:
            row = session.scalars(select(Evidence).where(Evidence.sha256 == sha256).limit(1)).first()
            ext = Path(row.path).suffix if row and row.path else ".bin"
        plain = settings.evidence_dir / f"{sha256}{ext}"
        if plain.is_file():
            return plain
        data = self.open_local(sha256)
        if data is None:
            return None
        tmp_dir = settings.data_dir / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        target = tmp_dir / f"{sha256}{ext}"
        target.write_bytes(data)
        return target

    # ------------------------------------------------------ 推送
    def _evidence_rows(self, session: Session, since_id: int = 0) -> list[Evidence]:
        return list(
            session.scalars(select(Evidence).where(Evidence.id > since_id).order_by(Evidence.id)).all()
        )

    def _asset_of(self, session: Session, asset_id: int) -> Asset | None:
        return session.get(Asset, asset_id)

    def _measure(self, row: Evidence) -> Path | None:
        for candidate in (
            settings.data_dir / row.path,
            settings.evidence_dir / Path(row.path).name,
            settings.evidence_dir / f"{row.sha256}.bin",
        ):
            if candidate.is_file():
                return candidate
        return None

    def push(self, *, limit: int = 500) -> dict[str, Any]:
        if not settings.vault_enabled:
            return {"ok": False, "reason": "证据仓未启用"}
        lock = self._file_lock()
        pushed = 0
        bytes_sent = 0
        try:
            backend = self._backend()
            done = {e["evidence"]["sha256"] for e in self.read_manifest(self.manifest_path)}
            with session_scope() as session:
                rows = self._evidence_rows(session)
                for row in rows:
                    if pushed >= limit:
                        break
                    if row.sha256 in done:
                        continue
                    path = self._measure(row)
                    if path is None:
                        # 明文已被清理但本地密文在——补账即可
                        if self._local_blob_path(row.sha256).is_file():
                            blob = self._local_blob_path(row.sha256).read_bytes()
                        else:
                            self._append_custody("missing", row.sha256, note="明文与密文均缺失")
                            continue
                    else:
                        data = path.read_bytes()
                        if hashlib.sha256(data).hexdigest() != row.sha256:
                            self._append_custody("corrupt", row.sha256, note="落盘文件哈希与记录不符")
                            continue
                        blob = self.seal_local(row.sha256, data)
                        self._append_custody(
                            "seal", row.sha256, size=len(data), alg="AES-256-GCM", key_id=self.keys.key_id
                        )
                        if settings.vault_remove_plaintext:
                            # 先记账再删文件：删失败也不会让「文件在哪」变成未知。
                            row.storage = "vault"
                            try:
                                path.unlink()
                                self._append_custody("redact-plaintext", row.sha256, path=str(path.name))
                            except OSError:
                                pass

                    copied = not (settings.vault_skip_same_device_copy and self.backend_same_device())
                    if copied:
                        locator = backend.put(self._blob_name(row.sha256), blob)
                    else:
                        # 密文已经在本地 vault/blobs 里，再往同盘「远端」写一份纯属浪费
                        locator = "local:" + self._blob_name(row.sha256)
                    asset = self._asset_of(session, row.asset_id)
                    entry = self._append_manifest(
                        {
                            "v": 1,
                            "evidence": {
                                "sha256": row.sha256,
                                "kind": row.kind,
                                "size": row.size,
                                "note": row.note[:500],
                                "ext": Path(row.path).suffix if row.path else ".bin",
                                "captured_at": row.captured_at.isoformat() if row.captured_at else "",
                            },
                            "asset": {
                                "kind": asset.kind if asset else "",
                                "value": asset.value if asset else "",
                                "normalized": asset.normalized if asset else "",
                                "fingerprint": asset.fingerprint if asset else "",
                                # 判断结果一并带走，新节点拉到的不是一堆"未研判"，而是同样的优先级
                                "tier": asset.tier if asset else TIER_CANDIDATE,
                                "score": round(float(asset.score), 2) if asset else 0.0,
                                "confidence": round(float(asset.confidence), 3) if asset else 0.0,
                                "verdict": asset.verdict if asset else "insufficient",
                                "discovery_source": asset.discovery_source if asset else "",
                                "discovery_reason": (asset.discovery_reason or "")[:300] if asset else "",
                                "first_seen": asset.first_seen.isoformat() if asset and asset.first_seen else "",
                            },
                            "blob": {
                                "backend": backend.name,
                                "name": self._blob_name(row.sha256),
                                "locator": locator,
                            },
                        }
                    )
                    self._append_custody(
                        "upload", row.sha256, backend=backend.name, locator=locator, entry=entry["hash"]
                    )
                    pushed += 1
                    if copied:
                        bytes_sent += len(blob)
                    done.add(row.sha256)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

        if pushed and not (settings.vault_skip_same_device_copy and self.backend_same_device()):
            self._publish_ledger()
        self.state.last_push = utcnow().isoformat()
        self.state.pushed += pushed
        self.state.pushed_bytes += bytes_sent
        self._save_state()
        return {"ok": True, "pushed": pushed, "bytes": bytes_sent, "node": self.node_id}

    def dedupe_remote(self, *, dry_run: bool = True, limit: int = 0) -> dict[str, Any]:
        """删掉远端与本地重复的密文副本。

        只处理后端是 dir 且与本地同盘的情况——这种「远端」不是备份，
        是同盘第二份；留着只占空间。删除条件严格：本地必须有同 sha 的密文，
        且大小完全一致。本地没有的远端对象一律不动，避免删出真丢失。
        """
        if settings.vault_backend != "dir":
            return {"ok": False, "reason": "只处理 dir 后端", "removed": 0}
        backend = self._backend()
        removed = freed = kept = 0
        targets: list[str] = []
        for name in backend.list("blobs/"):
            sha = Path(name).stem
            local = blob_path(sha)
            if not local.is_file():
                kept += 1
                continue
            size = backend.size(name)
            try:
                local_size = local.stat().st_size
            except OSError:
                kept += 1
                continue
            if size is not None and size != local_size:
                kept += 1
                continue
            targets.append(name)
        for name in targets:
            if limit and removed >= limit:
                break
            size = backend.size(name) or 0
            if dry_run:
                removed += 1
                freed += size
                continue
            try:
                if backend.delete(name):
                    removed += 1
                    freed += size
            except NotImplementedError:
                return {"ok": False, "reason": "后端不支持删除", "removed": removed}
        return {"ok": True, "dry_run": dry_run, "removed": removed,
                "freed_bytes": freed, "kept_remote_only": kept}

    def _publish_ledger(self) -> None:
        backend = self._backend()
        for path in (self.manifest_path, self.custody_path):
            if path.is_file():
                backend.put(f"ledger/{path.name}", path.read_bytes())

    # ------------------------------------------------------ 拉取
    def _pull_manifests(self) -> list[tuple[str, list[dict[str, Any]]]]:
        backend = self._backend()
        all_names = [n for n in backend.list("ledger/") if n.endswith(".jsonl")]
        # 顺带把其他节点的保管链也拉下来，便于第三方独立审计
        for name in all_names:
            if "custody-" not in name:
                continue
            data = backend.get(name)
            if data:
                self.remote_ledger_dir.mkdir(parents=True, exist_ok=True)
                _atomic_write(self.remote_ledger_dir / Path(name).name, data)
        names = [n for n in all_names if "custody-" not in n]
        if not names:
            for path in self.remote_ledger_dir.glob("*.jsonl") if self.remote_ledger_dir.is_dir() else []:
                names.append(f"ledger/{path.name}")
        out: list[tuple[str, list[dict[str, Any]]]] = []
        for name in names:
            data = backend.get(name)
            if data is None:
                path = self.ledger_dir / "remote" / Path(name).name
                if not path.is_file():
                    continue
                data = path.read_bytes()
            self.remote_ledger_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.remote_ledger_dir / Path(name).name, data)
            entries: list[dict[str, Any]] = []
            for raw in data.splitlines():
                if not raw.strip():
                    continue
                try:
                    entries.append(json.loads(raw))
                except json.JSONDecodeError:
                    break
            out.append((name, entries))
        return out

    def pull(self, *, limit: int = 500) -> dict[str, Any]:
        if not settings.vault_enabled:
            return {"ok": False, "reason": "证据仓未启用"}
        lock = self._file_lock()
        imported = 0
        bytes_in = 0
        skipped = 0
        try:
            backend = self._backend()
            manifests = self._pull_manifests()
            self.state.remote_entries = sum(len(entries) for _, entries in manifests)
            known: set[str] = set()
            with session_scope() as session:
                known = {sha for (sha,) in session.execute(select(Evidence.sha256)).all()}

            for name, entries in manifests:
                origin = (entries[0].get("node") if entries else Path(name).stem) or Path(name).stem
                for entry in entries:
                    if imported >= limit:
                        break
                    sha = (entry.get("evidence") or {}).get("sha256")
                    if not sha or sha in known:
                        skipped += 1
                        continue
                    blob = backend.get((entry.get("blob") or {}).get("name") or self._blob_name(sha))
                    if blob is None:
                        continue
                    try:
                        data = _open_with_length(blob, self.keys.key, sha)
                    except VaultError as exc:
                        self._append_custody("reject", sha, origin=origin, reason=str(exc))
                        continue
                    if hashlib.sha256(data).hexdigest() != sha:
                        self._append_custody("reject", sha, origin=origin, reason="哈希不符")
                        continue

                    asset_info = entry.get("asset") or {}
                    ev_info = entry.get("evidence") or {}
                    ext = str(ev_info.get("ext") or ".bin")
                    if not ext.startswith("."):
                        ext = "." + ext
                    target = settings.evidence_dir / f"{sha}{ext}"
                    if not target.is_file():
                        _atomic_write(target, data)
                    self.seal_local(sha, data)

                    with session_scope() as session:
                        asset = self._upsert_asset(session, asset_info)
                        last = session.scalars(
                            select(Evidence).order_by(Evidence.id.desc()).limit(1)
                        ).first()
                        prev_hash = last.chain_hash if last else ""
                        from .db import compute_chain_hash

                        captured = utcnow()
                        try:
                            from datetime import datetime

                            if ev_info.get("captured_at"):
                                captured = datetime.fromisoformat(str(ev_info["captured_at"]))
                        except (ValueError, TypeError):
                            pass
                        row = Evidence(
                            asset_id=asset.id,
                            kind=str(ev_info.get("kind") or "blob")[:32],
                            sha256=sha,
                            prev_hash=prev_hash,
                            size=int(ev_info.get("size") or len(data)),
                            path=str(target.relative_to(settings.data_dir))
                            if target.is_relative_to(settings.data_dir)
                            else str(target),
                            note=str(ev_info.get("note") or "")[:500],
                            captured_at=captured,
                        )
                        row.chain_hash = compute_chain_hash(prev_hash, sha, captured.isoformat())
                        session.add(row)
                        session.flush()
                        local_id = row.id
                    self._append_custody("download", sha, origin=origin, backend=backend.name)
                    self._append_custody("import", sha, origin=origin, local_id=str(local_id))
                    known.add(sha)
                    imported += 1
                    bytes_in += len(data)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

        self.state.last_pull = utcnow().isoformat()
        self.state.pulled += imported
        self.state.pulled_bytes += bytes_in
        self._save_state()
        return {
            "ok": True,
            "imported": imported,
            "skipped": skipped,
            "bytes": bytes_in,
            "remote_nodes": len(manifests),
            "remote_entries": self.state.remote_entries,
        }

    def _upsert_asset(self, session: Session, info: dict[str, Any]) -> Asset:
        """按「只升不降」合并：分级取更强的一档，分数取更高的一档。"""
        from .models import TIER_ORDER

        kind = str(info.get("kind") or "domain")[:16]
        value = str(info.get("value") or "")[:2000]
        normalized = str(info.get("normalized") or value)[:2000]
        tier = str(info.get("tier") or TIER_CANDIDATE)
        if tier not in TIER_ORDER:
            tier = TIER_CANDIDATE
        incoming_score = float(info.get("score") or 0.0)
        incoming_conf = float(info.get("confidence") or 0.0)

        asset = session.scalars(
            select(Asset).where(Asset.kind == kind, Asset.normalized == normalized).limit(1)
        ).first()
        if asset is None:
            asset = Asset(
                kind=kind,
                value=value,
                normalized=normalized,
                fingerprint=str(info.get("fingerprint") or "")[:64],
                tier=tier,
                score=incoming_score,
                confidence=incoming_conf,
                verdict=str(info.get("verdict") or "insufficient")[:24],
                discovery_source=str(info.get("discovery_source") or "vault")[:32],
                discovery_reason=str(info.get("discovery_reason") or "")[:500],
            )
            first_seen = info.get("first_seen")
            if first_seen:
                try:
                    from datetime import datetime

                    asset.first_seen = datetime.fromisoformat(str(first_seen))
                except (ValueError, TypeError):
                    pass
            session.add(asset)
            session.flush()
            return asset

        # 只升不降：confirmed > watch > candidate > cold > dismissed
        if TIER_ORDER.index(tier) < TIER_ORDER.index(asset.tier):
            asset.tier = tier
        if incoming_score > asset.score:
            asset.score = incoming_score
            asset.confidence = max(asset.confidence, incoming_conf)
            if info.get("verdict"):
                asset.verdict = str(info["verdict"])[:24]
        if not asset.discovery_source and info.get("discovery_source"):
            asset.discovery_source = str(info["discovery_source"])[:32]
        return asset

    # ------------------------------------------------------ 校验
    def verify(self, *, deep: bool = True, sample: int = 50) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": True, "nodes": [], "checked": 0, "blobs_checked": 0}
        remote_all = sorted(self.remote_ledger_dir.glob("*.jsonl")) if self.remote_ledger_dir.is_dir() else []
        paths = [self.manifest_path] + [
            p for p in remote_all
            if not p.name.startswith("custody-") and p.name != self.manifest_path.name
        ]
        for path in paths:
            entries = self.read_manifest(path)
            prev = GENESIS
            broken = None
            for i, entry in enumerate(entries, 1):
                if int(entry.get("seq", 0)) != i:
                    broken = f"第 {i} 条序号断裂"
                    break
                if entry.get("prev") != prev:
                    broken = f"第 {i} 条前序哈希不符"
                    break
                if _hash_entry(entry) != entry.get("hash"):
                    broken = f"第 {i} 条内容哈希不符"
                    break
                prev = entry["hash"]
            result["nodes"].append(
                {"file": path.name, "entries": len(entries), "head": prev, "ok": broken is None, "reason": broken or ""}
            )
            if broken:
                result["ok"] = False
            result["checked"] += len(entries)

        # 各节点保管链（本地 + 远端副本）
        for custody in [self.custody_path] + [
            p for p in remote_all
            if p.name.startswith("custody-") and p.name != self.custody_path.name
        ]:
            if not custody.is_file():
                continue
            entries = self.read_manifest(custody)
            prev = GENESIS
            broken = None
            for i, entry in enumerate(entries, 1):
                if int(entry.get("seq", 0)) != i or entry.get("prev") != prev or _hash_entry(entry) != entry.get("hash"):
                    broken = f"第 {i} 条保管链断裂"
                    break
                prev = entry["hash"]
            key = "custody" if custody == self.custody_path else f"custody:{custody.name}"
            result[key] = {"entries": len(entries), "ok": broken is None, "reason": broken or ""}
            if broken:
                result["ok"] = False

        if deep:
            checked = 0
            for entry in self.read_manifest(self.manifest_path)[-sample:]:
                sha = entry["evidence"]["sha256"]
                path = self._local_blob_path(sha)
                if not path.is_file():
                    result.setdefault("missing_blobs", []).append(sha)
                    continue
                try:
                    data = _open_with_length(path.read_bytes(), self.keys.key, sha)
                    if hashlib.sha256(data).hexdigest() != sha:
                        result.setdefault("bad_blobs", []).append(sha)
                except VaultError:
                    result.setdefault("bad_blobs", []).append(sha)
                checked += 1
            result["blobs_checked"] = checked
            if result.get("missing_blobs") or result.get("bad_blobs"):
                result["ok"] = False
        return result

    # ------------------------------------------------------ 导出账本
    def export_ledger(self, dest: str | Path) -> dict[str, Any]:
        """只导出可公开的「固定证据」：账本 + 保管链 + SHA-256 清单，不含密文与密钥。"""
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        if self.manifest_path.is_file():
            files.append(self.manifest_path)
        if self.custody_path.is_file():
            files.append(self.custody_path)
        if self.remote_ledger_dir.is_dir():
            files.extend(sorted(self.remote_ledger_dir.glob("*.jsonl")))
        for path in files:
            shutil.copy2(path, dest / path.name)

        lines = []
        for path in sorted(dest.glob("*.jsonl")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.name}")
        (dest / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

        readme = dest / "README.md"
        if not readme.is_file():
            readme.write_text(
                "# 证据账本（仅固定信息）\n\n"
                "本目录只包含 SHA-256、逐条哈希链与保管链记录，**不含任何原始证据文件**。\n"
                "原始文件以 AES-256-GCM 加密存放在私有/去中心化存储，密钥不随仓库分发。\n\n"
                "校验方式：\n\n"
                "```bash\n"
                "sha256sum -c SHA256SUMS\n"
                "silver-sentinel vault verify\n"
                "```\n\n"
                "字段说明：`seq` 序号、`prev` 前序哈希、`hash` 本条哈希、`evidence.sha256` 明文摘要、\n"
                "`blob.locator` 密文位置（CID 或对象键）、`custody` 记录采集/加密/上传/下载/导入全过程。\n",
                encoding="utf-8",
            )
        return {"ok": True, "dir": str(dest), "files": len(files)}

    def import_ledger(self, src: str | Path) -> dict[str, Any]:
        src = Path(src)
        self.remote_ledger_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for path in sorted(src.glob("*.jsonl")):
            if path.name.startswith(f"custody-{self.node_id}"):
                continue
            shutil.copy2(path, self.remote_ledger_dir / path.name)
            count += 1
        entries = sum(len(self.read_manifest(p)) for p in self.remote_ledger_dir.glob("*.jsonl"))
        return {"ok": True, "files": count, "entries": entries}

    # ------------------------------------------------------ 同步循环
    def sync_once(self, *, include_push: bool = True) -> dict[str, Any]:
        started = time.monotonic()
        result: dict[str, Any] = {"ok": True}
        try:
            result["pull"] = self.pull()
            if include_push:
                result["push"] = self.push()
            self.state.last_error = ""
        except Exception as exc:  # noqa: BLE001
            self.state.last_error = f"{type(exc).__name__}: {exc}"[:300]
            result = {"ok": False, "error": self.state.last_error}
            log.warning("证据仓同步失败：%s", exc)
        result["elapsed"] = round(time.monotonic() - started, 2)
        self.state.history.append({"at": utcnow().isoformat(), **result})
        self._save_state()
        return result

    def start(self) -> None:
        if not settings.vault_enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="vault-sync", daemon=True)
        self._thread.start()
        log.info("证据仓同步已启动：%s -> %s", self.node_id, settings.vault_target)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        # 启动先跑一次，把已有证据固化
        self.sync_once()
        while not self._stop.wait(max(30, settings.vault_interval)):
            self.sync_once()

    # ------------------------------------------------------ 状态
    def status(self) -> dict[str, Any]:
        manifests = []
        remote_all = sorted(self.remote_ledger_dir.glob("*.jsonl")) if self.remote_ledger_dir.is_dir() else []
        for path in [self.manifest_path] + [
            p for p in remote_all
            if not p.name.startswith("custody-") and p.name != self.manifest_path.name
        ]:
            entries = self.read_manifest(path)
            manifests.append(
                {
                    "file": path.name,
                    "node": entries[0].get("node") if entries else "",
                    "entries": len(entries),
                    "head": entries[-1]["hash"][:16] if entries else "",
                }
            )
        local_entries = len(self.read_manifest(self.manifest_path))
        from sqlalchemy import func

        with session_scope() as session:
            total_evidence = session.scalar(select(func.max(Evidence.id))) or 0
            count = session.scalar(select(func.count(Evidence.id))) or 0
        return {
            "enabled": settings.vault_enabled,
            "backend": settings.vault_backend,
            "target_set": bool(settings.vault_target),
            "target_same_device": self.backend_same_device(),
            "skip_same_device_copy": settings.vault_skip_same_device_copy,
            "node": self.node_id,
            "key_id": self.keys.key_id if self._key_present() else "missing",
            "evidence_total": count,
            "ledger_entries": local_entries,
            "pending": max(0, count - local_entries),
            "manifests": manifests,
            "state": self.state.to_dict(),
            "blob_bytes": sum(p.stat().st_size for p in self.local_blob_dir.rglob("*.ssv"))
            if self.local_blob_dir.is_dir()
            else 0,
            "last_evidence_id": total_evidence,
        }

    def _key_present(self) -> bool:
        try:
            _ = self.keys.key
            return True
        except VaultError:
            return False


_vault: Vault | None = None
_vault_lock = threading.Lock()


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        with _vault_lock:
            if _vault is None:
                _vault = Vault()
    return _vault
