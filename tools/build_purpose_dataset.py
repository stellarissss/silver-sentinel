"""构建「用途分类」数据集：抓真实站点 → 抽特征 → 落 JSONL。

为什么用 Playwright 而不是 requests
----------------------------------
线上取证走的是渲染后的 DOM（有 network、forms、真实正文）。训练集必须用
同一条链路，否则特征分布不一致——模型在训练集上 0.95，上线就崩。

用法
----
    python3 tools/build_purpose_dataset.py --out data/purpose_seed.jsonl
    python3 tools/build_purpose_dataset.py --out data/purpose_seed.jsonl --resume
    python3 tools/build_purpose_dataset.py --only customer_service,forum

输出每行：
    {"host":..., "url":..., "label":..., "ok":true, "features":{...}, "hints":[...]}

标签是我按站点性质人工指定的，属于「弱监督种子集」，不是金标准。它的用途是
把特征空间与规则基线校准到同一套口径；真正的标签会随线上 confirmed/dismissed
持续回流（见 docs/25）。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# 人工种子清单。每类尽量覆盖不同规模、不同 CMS、不同地区，
# 避免模型学到「某个模板 = 某个用途」。
SEEDS: dict[str, list[str]] = {
    # 政府类刻意留空：opsec 的禁访清单不允许主动触碰 .gov.cn（查询无收益、
    # 易触发风控）。政府站靠白名单确定性判定，不需要模型学，也学不到。
    "government": [],
    "news": [
        "http://www.people.com.cn/", "http://www.xinhuanet.com/", "https://www.cctv.com/",
        "https://www.thepaper.cn/", "https://www.chinanews.com.cn/", "https://www.gmw.cn/",
        "http://www.ce.cn/", "http://www.youth.cn/", "https://www.legaldaily.com.cn/",
        "https://www.caixin.com/", "https://36kr.com/", "https://www.ithome.com/",
        "https://news.sina.com.cn/", "https://news.163.com/", "https://www.ifeng.com/",
        "https://www.jiemian.com/", "https://www.yicai.com/", "https://www.stcn.com/",
    ],
    "customer_service": [
        "https://www.53kf.com/", "https://www.meiqia.com/", "https://www.sobot.com/",
        "https://www.zhichi.com/", "https://www.udesk.cn/", "https://www.7moor.com/",
        "https://www.kf5.com/", "https://www.live800.com/", "https://qiyu.163.com/",
        "https://www.easemob.com/", "https://www.hihoocn.com/", "https://www.ti-net.com.cn/",
        "https://www.zkcrm.com/", "https://www.goodsfw.com/",
    ],
    "forum": [
        "https://bbs.tianya.cn/", "https://bbs.hupu.com/", "https://www.19lou.com/",
        "https://www.55bbs.com/", "https://www.douban.com/group/", "https://tieba.baidu.com/",
        "https://www.zhihu.com/", "https://www.v2ex.com/", "https://www.kdslife.com/",
        "https://www.nga.cn/", "https://bbs.ngacn.cc/", "https://www.mcbbs.net/",
        "https://www.gcores.com/", "https://www.jisilu.cn/",
    ],
    "ecommerce": [
        "https://www.jd.com/", "https://www.suning.com/", "https://www.vip.com/",
        "https://www.dangdang.com/", "https://www.yiwugo.com/", "https://www.1688.com/",
        "https://www.made-in-china.com/", "https://www.dhgate.com/", "https://www.zhaopin.com/",
        "https://www.kaola.com/", "https://www.mogu.com/", "https://www.yhd.com/",
        "https://www.jumei.com/", "https://www.taobao.com/",
    ],
    "corporate": [
        "https://www.yige-tech.com/", "https://www.yonyou.com/", "https://www.kingdee.com/",
        "https://www.weaver.com.cn/", "https://www.hand-china.com/", "https://www.neusoft.com/",
        "https://www.inspur.com/", "https://www.huawei.com/cn/", "https://www.lenovo.com.cn/",
        "https://www.aliyun.com/", "https://www.h3c.com/cn/", "https://www.zte.com.cn/china/",
        "https://www.sangfor.com.cn/", "https://www.yonyoucloud.com/",
    ],
    "portal": [
        "https://www.yanglaocn.com/", "https://www.39.net/", "https://www.chealth.org.cn/",
        "http://www.cncaprc.gov.cn/", "https://www.redcross.org.cn/", "https://www.jianke.com/",
        "https://www.xywy.com/", "https://www.99.com.cn/", "https://www.familydoctor.com.cn/",
        "https://www.guokr.com/", "https://www.dxy.cn/", "https://www.medsci.cn/",
    ],
    "app_dist": [
        "https://sj.qq.com/", "https://www.wandoujia.com/", "https://app.mi.com/",
        "https://appgallery.huawei.com/", "https://www.coolapk.com/", "https://www.apkpure.com/",
        "https://www.pgyer.com/", "https://www.fir.im/",
    ],
    # 落地页/分发页：诈骗高发形态。训练它们是为了让模型「不要把这类判成企业站」。
    "landing": [
        "https://np4w53.cn/?&member=bt", "https://hksm38.com.cn/", "https://s.qka91.com/",
        "https://huicetong.com.cn/", "https://bpcnh.xyz/", "https://xindazx.cn/",
        "https://nuanyang-website.pages.dev/", "https://n456y.top/",
    ],
}

MAX_HTML = 900_000


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="src/silver_sentinel/data/purpose_seed.jsonl")
    ap.add_argument("--resume", action="store_true", help="跳过已抓过的 host")
    ap.add_argument("--only", default="", help="只跑这些标签，逗号分隔")
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--limit", type=int, default=0, help="每类最多抓几个（调试用）")
    args = ap.parse_args()

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    done: set[str] = set()
    if args.resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                if row.get("ok"):
                    done.add(row.get("host") or "")
            except json.JSONDecodeError:
                continue

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    labels = [k for k in SEEDS if not only or k in only]

    from silver_sentinel.claim import analyze_html
    from silver_sentinel.features import extract
    from silver_sentinel.sandbox.web import get_web_sandbox
    from silver_sentinel.whitelist import get_whitelist

    sandbox = get_web_sandbox()
    wl = get_whitelist()
    stats: dict[str, int] = {"ok": 0, "fail": 0}

    with out_path.open("a", encoding="utf-8") as fh:
        for label in labels:
            urls = SEEDS[label][: args.limit] if args.limit else SEEDS[label]
            for url in urls:
                host = _host(url)
                if not host or host in done:
                    continue
                started = time.time()
                obs = sandbox.observe(url, timeout=args.timeout)
                # 反爬/SPA 站点常常只返回几十个字的骨架页，这类样本会把
                # 「文字少」学成「落地页」，必须丢掉。诈骗落地页本身短，除外。
                text_len = len(obs.text or "")
                if not (obs.html or obs.text):
                    stats["fail"] += 1
                    print(f"  ✗ {label:<17} {host:<28} {obs.error[:60]}")
                    fh.write(json.dumps({"host": host, "url": url, "label": label,
                                         "ok": False, "error": (obs.error or "无内容")[:200]},
                                        ensure_ascii=False) + "\n")
                    fh.flush()
                    continue

                if text_len < 200 and label not in ("landing", "app_dist"):
                    stats["fail"] += 1
                    print(f"  ~ {label:<17} {host:<28} 正文仅 {text_len} 字，跳过（疑似反爬/SPA）")
                    fh.write(json.dumps({"host": host, "url": url, "label": label,
                                         "ok": False, "error": f"正文过短 {text_len}"},
                                        ensure_ascii=False) + "\n")
                    fh.flush()
                    continue

                facts = {"is_government": wl.is_government(host), "is_media": wl.is_media(host)}
                try:
                    if obs.html:
                        facts["claim"] = analyze_html(obs.html[:MAX_HTML], host).as_dict()
                except Exception as exc:  # noqa: BLE001
                    facts["claim_error"] = str(exc)[:120]

                bundle = extract(
                    url=obs.final_url or url, html=obs.html[:MAX_HTML], text=obs.text,
                    facts=facts, requests=obs.requests, forms=obs.forms, tls=obs.tls,
                    apk_links=obs.apk_links,
                )
                row = {
                    "host": host,
                    "url": obs.final_url or url,
                    "label": label,
                    "ok": True,
                    "title": (obs.title or "")[:120],
                    "features": bundle.as_dict(),
                    "hints": bundle.hints,
                    "facts": {"is_government": facts.get("is_government", False),
                              "is_media": facts.get("is_media", False),
                              "claim": facts.get("claim") or {}},
                    "elapsed": round(time.time() - started, 1),
                }
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                fh.flush()
                stats["ok"] += 1
                print(f"  ✓ {label:<17} {host:<28} text={int(bundle.values.get('text_len', 0)):<6} "
                      f"{round(time.time() - started, 1)}s  {bundle.hints[:2]}")

    print(f"\n完成：成功 {stats['ok']}，失败 {stats['fail']}，输出 {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
