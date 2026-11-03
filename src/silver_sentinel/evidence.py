"""证据存储与哈希链。

每条证据的 chain_hash = H(上一条 chain_hash | 本条 sha256 | 采集时间)。
删一条、改一条、换顺序，链都会断——这是事后向监管/公安提交材料时的自证基础。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .domain import utcnow
from .db import compute_chain_hash
from .models import Evidence


def chain_tip(session: Session) -> str:
    row = session.scalars(select(Evidence).order_by(Evidence.id.desc()).limit(1)).first()
    return row.chain_hash if row else ""


def append(
    session: Session,
    asset_id: int,
    kind: str,
    data: bytes,
    *,
    note: str = "",
    extension: str = ".bin",
) -> Evidence:
    digest = hashlib.sha256(data).hexdigest()
    target = settings.evidence_dir / f"{digest}{extension}"
    if not target.exists():
        target.write_bytes(data)

    prev = chain_tip(session)
    captured = utcnow()  # 必须显式赋值：列默认值在 flush 时才生效，那时已经要算哈希了
    row = Evidence(
        asset_id=asset_id,
        kind=kind,
        sha256=digest,
        prev_hash=prev,
        size=len(data),
        captured_at=captured,
        path=str(target.relative_to(settings.data_dir)) if target.is_relative_to(settings.data_dir) else str(target),
        note=note,
    )
    row.chain_hash = compute_chain_hash(prev, digest, captured.isoformat())
    session.add(row)
    session.flush()
    return row


def append_file(session: Session, asset_id: int, kind: str, path: str | Path, note: str = "") -> Evidence:
    path = Path(path)
    return append(session, asset_id, kind, path.read_bytes(), note=note, extension=path.suffix or ".bin")
