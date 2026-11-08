"""直连取证书，把 SAN 里的域名全挖出来。

为什么必须做这一步
------------------
2026-11 实测 np4w53.cn 的证书：

    Issuer:  TrustAsia / LiteSSL RSA CA 2025
    Subject: CN = oi6o45.cn
    SAN:     oi6o45.cn, uw2v71.cn, tx7y28.cn, np4w53.cn, bv1m97.cn, ...
             （共 90 个）

抽 10 个测存活：9 个在线、同一个 IP（204.194.55.233）、标题逐字相同
（`2026年个人财政补贴申领`）。而我们库里只有 1 个。

一张证书 = 一个批次的全部域名。这是「广泛」唯一的物理量：
骗子可以一天换一个域名，但换域名就要重新签证书，而重签时会把
整批域名一起写进 SAN——因为那是一个脚本干的。

为什么不用 certspotter / crt.sh
-------------------------------
它们要外部配额，且有延迟。而证书就在 TLS 握手里，一次 200 毫秒，
标准库就能拿到。对已经确定要取证的站，这一步是免费的。
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class CertInfo:
    host: str
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    # SAN 里的全部 DNS 名。通配符已经剥掉前缀，注册域由调用方归并。
    dns_names: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.dns_names or self.subject)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "dns_count": len(self.dns_names),
            "dns_names": self.dns_names[:120],
            "error": self.error,
        }


def _name_of(rdns: tuple) -> str:
    """把 ((('commonName','x'),),) 压成 'x'。"""
    out = []
    for part in rdns or ():
        for k, v in part:
            if k in ("commonName", "organizationName"):
                out.append(str(v))
    return " / ".join(out)


def _fmt_time(v: str) -> str:
    if not v:
        return ""
    try:
        dt = datetime.strptime(v, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return dt.isoformat()
    except ValueError:
        return v


def fetch(host: str, *, port: int = 443, timeout: float = 8.0) -> CertInfo:
    """连一次拿证书。失败返回带 error 的空对象，不抛异常。

    刻意关闭证书校验：目标是骗子的站，证书链本来就不可信，我们要的是
    证书里的**内容**（SAN 名单），不是「它是否可信」。
    """
    info = CertInfo(host=host)
    host = (host or "").strip().lower()
    if not host or "." not in host:
        info.error = "无效域名"
        return info
    try:
        ipaddress.ip_address(host)
        info.error = "目标是 IP，没有证书主体"
        return info
    except ValueError:
        pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    info.error = "对端未提供证书"
                    return info
                parsed = ssock.getpeercert() or {}
                # CERT_NONE 下 getpeercert() 常常返回空 dict，退回手工解析
                if not parsed:
                    parsed = _decode_der(der)
                info.subject = _name_of(parsed.get("subject"))
                info.issuer = _name_of(parsed.get("issuer"))
                info.not_before = _fmt_time(parsed.get("notBefore", ""))
                info.not_after = _fmt_time(parsed.get("notAfter", ""))
                info.serial = str(parsed.get("serialNumber", ""))
                names: list[str] = []
                for kind, value in parsed.get("subjectAltName") or ():
                    if kind != "DNS":
                        continue
                    n = str(value).lower().strip(".")
                    if n.startswith("*."):
                        n = n[2:]
                    if n and "." in n and n not in names:
                        names.append(n)
                info.dns_names = names
    except (OSError, ssl.SSLError) as exc:
        info.error = f"{type(exc).__name__}: {exc}"[:120]
    return info


def _decode_der(der: bytes) -> dict:
    """DER → python dict。用 cryptography 库，失败返回空。"""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        names = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = [("DNS", n) for n in ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            pass
        return {
            "subject": ((("commonName", cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value),),) if cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME) else (),
            "issuer": ((("commonName", cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value),),) if cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME) else (),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "serialNumber": format(cert.serial_number, "X"),
            "subjectAltName": tuple(names),
        }
    except Exception:  # noqa: BLE001 解不出来就当没有 SAN，不影响取证
        return {}
