#!/usr/bin/env python3
"""重建白名单数据文件。

    python tools/build_whitelist.py                 # 联网拉三源
    python tools/build_whitelist.py --gov-csv x.csv --news-json y.json --cac-pdf z.pdf

产出：

    src/silver_sentinel/data/gov_sites.csv.gz   13k 条政府网站（host, name, level）
    src/silver_sentinel/data/media_sites.txt    351 个新闻媒体域名

数据来源与坑
------------
1. 政府网站数据库（zfwzzc.www.gov.cn）**境外直连会超时**——这是 Brussee
   论文里说的 reverse GFW。所以默认走他在 Zenodo 的快照：
   https://zenodo.org/records/18172145
2. 网信办《稿源单位名单》是 PDF，**只有单位名没有 URL**。必须靠一个
   域名库反查：
   https://github.com/Force1ess/Chinese-News-Domains（10,000 条 名称→域名）
   匹配率约 44%，其余是报纸/期刊/电视台，本来就没有独立网站。
3. 那份 10,000 条域名库**质量不行**（含论坛、彩票站），只能用来做名称映射，
   不能整体当白名单。
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "src" / "silver_sentinel" / "data"
GOV_OUT = DATA / "gov_sites.csv.gz"
MEDIA_OUT = DATA / "media_sites.txt"

ZENODO = "https://zenodo.org/records/18172145/files/Chinese%20government%20websites.csv?download=1"
NEWS_JSON = "https://raw.githubusercontent.com/Force1ess/Chinese-News-Domains/master/cn-news-domains.json"
CAC_PDF = "https://www.cac.gov.cn/rootimages/uploadimg/1756886952378281/1756886952378281.pdf"

# 中央新闻网站与重点理论网站（31 家）。稿源名单会给名字但不给域名，
# 这几家是漏不起的，直接写死。
CENTRAL = """
people.com.cn xinhuanet.com news.cn cctv.com cctv.cn china.com.cn cri.cn
chinadaily.com.cn youth.cn ce.cn taiwan.cn tibet.cn cnr.cn gmw.cn 81.cn
chinanews.com rmzxb.com.cn legaldaily.com.cn qstheory.cn xuexi.cn wenming.cn
chinaso.com haiwainet.cn k618.cn workercn.cn huanqiu.com jcrb.com cssn.cn
dangjian.com rmlt.com.cn chinacourt.org spp.gov.cn cnwest.com
""".split()


def _download(url: str, dst: Path) -> Path:
    print(f"  下载 {url[:90]} …", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as r, dst.open("wb") as f:
        f.write(r.read())
    return dst


def _host_of(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        return ""
    if "http" not in u:
        u = "http://" + u
    # 政府库有些行塞了两个 URL（分号/全角分号分隔），取第一个
    u = re.split(r"[;；]", u)[0]
    host = urllib.parse.urlparse(u).netloc.lower().split(":")[0].strip(". ")
    return host[4:] if host.startswith("www.") else host


def build_gov(csv_path: Path) -> int:
    rows = []
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            host = _host_of(r.get("url") or "")
            if not host or "." not in host:
                continue
            name = re.sub(r"\s+", " ", (r.get("name") or "")).strip()[:60]
            rows.append((host, name, (r.get("admin_level") or "").strip()))
    rows.sort()
    DATA.mkdir(parents=True, exist_ok=True)
    with gzip.open(GOV_OUT, "wt", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "name", "level"])
        w.writerows(rows)
    print(f"  政府库 {len(rows)} 行 → {GOV_OUT.relative_to(ROOT)}")
    return len(rows)


def _norm_name(s: str) -> str:
    return re.sub(r"(网站|网|在线|客户端)$", "", s or "").strip()


def build_media(news_json: Path, cac_pdf: Path) -> int:
    news = json.loads(news_json.read_text(encoding="utf-8"))
    by_name = {}
    by_norm = {}
    for name, domain in news:
        d = (domain or "").lower().split("/")[0]
        if not d or "." not in d:
            continue
        by_name[name] = d
        by_norm.setdefault(_norm_name(name), d)

    txt = ""
    if cac_pdf.exists():
        try:
            txt = subprocess.run(
                ["pdftotext", "-layout", str(cac_pdf), "-"],
                capture_output=True, text=True, timeout=60,
            ).stdout
        except Exception as exc:  # noqa: BLE001
            print(f"  pdftotext 失败（{exc}），只用中央站清单", file=sys.stderr)

    names = set(re.findall(r"[\u4e00-\u9fff]{2,20}(?:网|网站|在线|客户端)", txt))
    hosts = set()
    for n in names:
        d = by_name.get(n) or by_norm.get(_norm_name(n))
        if d:
            hosts.add(d.replace("www.", "", 1))

    hosts |= set(CENTRAL)
    hosts = {h for h in hosts if re.fullmatch(r"[a-z0-9.\-]+", h) and "." in h}
    if not hosts:
        raise SystemExit("媒体域名一个都没匹配上，检查输入文件")
    MEDIA_OUT.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")
    print(f"  媒体 {len(hosts)} 个（稿源匹配 {len(names)} 个站名）→ {MEDIA_OUT.relative_to(ROOT)}")
    return len(hosts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gov-csv", help="本地政府库 CSV（默认从 Zenodo 下载）")
    ap.add_argument("--news-json", help="本地新闻域名库 JSON（默认从 GitHub 下载）")
    ap.add_argument("--cac-pdf", help="本地稿源名单 PDF（默认从 cac.gov.cn 下载）")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        gov = Path(args.gov_csv) if args.gov_csv else _download(ZENODO, tmp / "gov.csv")
        news = Path(args.news_json) if args.news_json else _download(NEWS_JSON, tmp / "news.json")
        cac = Path(args.cac_pdf) if args.cac_pdf else _download(CAC_PDF, tmp / "cac.pdf")
        build_gov(gov)
        build_media(news, cac)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
