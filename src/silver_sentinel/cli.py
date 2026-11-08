"""命令行入口。

设计成「无服务也能用」：现场排查时，一条命令拿到结论和举报稿，
不需要先起 Web、不需要数据库管理界面。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .config import settings
from .db import init_db, session_scope, verify_chain
from .domain import VERDICT_LABELS
from .intake import scan
from .models import Asset
from .respond import advise, build, export_bundle
from .scoring.engine import load_ruleset

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, ORG, YEL, GRN, CYA = "\033[31m", "\033[38;5;208m", "\033[33m", "\033[32m", "\033[36m"

COLORS = {
    "confirmed": RED,
    "high_risk": ORG,
    "suspicious": YEL,
    "low": GRN,
    "insufficient": DIM,
    "benign": CYA,
}


def _color(verdict: str, text: str) -> str:
    return f"{COLORS.get(verdict, '')}{text}{RESET}"


def _print_assessment(result, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return

    a = result.assessment
    label = VERDICT_LABELS.get(a.verdict, a.verdict)
    print()
    print(f"{BOLD}{result.asset['value'][:90]}{RESET}")
    print(f"  {DIM}{result.asset['kind']} · {result.asset['normalized'][:90]}{RESET}")
    print(f"  判定 {_color(a.verdict, label)}  风险分 {BOLD}{a.score:.0f}{RESET}  置信 {a.confidence:.2f}  来源 {a.independent_sources}")
    print(f"  {DIM}{'─' * 66}{RESET}")

    if a.signals:
        for s in a.top_signals[:12]:
            print(f"  {_color(a.verdict, '•')} [{s.rule_id}] {s.title}  {DIM}({s.weight:.0f}/{s.confidence:.2f}){RESET}")
            if s.detail:
                print(f"      {DIM}{s.detail[:96]}{RESET}")
    else:
        print(f"  {DIM}未命中任何规则{RESET}")

    for note in a.notes:
        print(f"  {YEL}! {note}{RESET}")

    if a.llm:
        print(f"\n  {CYA}LLM 研判{RESET}（{a.llm['classification']} · {a.llm['stage']}）")
        print(f"  {a.llm['reasoning'][:300]}")

    print(f"\n  {BOLD}建议处置{RESET}")
    for i, item in enumerate(advise(a.verdict), 1):
        print(f"   {i}. {item}")
    print()


def cmd_scan(args) -> int:
    init_db()
    result = scan(
        args.kind,
        args.value,
        text=args.text,
        file_path=args.file,
        run_llm=not args.no_llm,
        meta={"distribution_channel": args.channel} if args.channel else None,
    )
    _print_assessment(result, args.json)
    return 0


def cmd_apk(args) -> int:
    init_db()
    path = Path(args.path)
    if not path.is_file():
        print(f"文件不存在：{path}", file=sys.stderr)
        return 2
    result = scan("apk", path.name, file_path=str(path), run_llm=not args.no_llm)
    _print_assessment(result, args.json)
    return 0


def cmd_list(args) -> int:
    init_db()
    with session_scope() as session:
        query = session.query(Asset).order_by(Asset.score.desc())
        if args.verdict:
            query = query.filter(Asset.verdict == args.verdict)
        rows = query.limit(args.limit).all()
        if not rows:
            print("暂无线索。")
            return 0
        print(f"{'ID':>4}  {'判定':<10} {'分':>5}  {'类型':<8} 标识")
        for a in rows:
            label = VERDICT_LABELS.get(a.verdict, a.verdict)
            print(f"{a.id:>4}  {_color(a.verdict, f'{label:<10}')} {a.score:>5.0f}  {a.kind:<8} {a.value[:70]}")
    return 0


def cmd_report(args) -> int:
    init_db()
    with session_scope() as session:
        try:
            if args.bundle:
                data = export_bundle(session, args.asset_id)
                text = json.dumps(data, ensure_ascii=False, indent=2)
            else:
                draft = build(session, args.asset_id, args.channel)
                text = draft.body
        except LookupError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已写入 {args.out}")
    else:
        print(text)
    return 0


def cmd_watch(args) -> int:
    from .models import WatchTarget
    from .monitor import run_due

    init_db()
    if args.action == "add":
        with session_scope() as session:
            exists = (
                session.query(WatchTarget)
                .filter(WatchTarget.kind == args.kind, WatchTarget.value == args.value)
                .first()
            )
            if exists:
                print(f"已存在：#{exists.id}")
                return 0
            target = WatchTarget(kind=args.kind, value=args.value, interval_minutes=args.interval)
            session.add(target)
            session.flush()
            print(f"已添加监控 #{target.id}：{args.kind}={args.value}，每 {args.interval} 分钟")
    elif args.action == "list":
        with session_scope() as session:
            rows = session.query(WatchTarget).all()
            if not rows:
                print("暂无监控目标。")
                return 0
            for t in rows:
                print(f"#{t.id:<3} {t.kind:<8} {t.value:<30} 每 {t.interval_minutes} 分钟  "
                      f"上次 {t.last_run_at.strftime('%m-%d %H:%M') if t.last_run_at else '—'}")
    elif args.action == "run":
        results = run_due()
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args) -> int:
    init_db()
    with session_scope() as session:
        result = verify_chain(session, args.asset)
    if result.get("ok"):
        print(f"{GRN}证据链完好{RESET}：已校验 {result['checked']} 条，链头 {result['head'][:16]}…")
        return 0
    print(f"{RED}证据链异常{RESET}：在证据 #{result.get('broken_at')} 处断开")
    return 1


def cmd_trash(args) -> int:
    """回收站：看被软删的证据，或按时间物理清理。

    软删除只是把文件挪进 trash/ 并在库里留 tombstone。记录永远不删，
    但文件会一直占盘，所以留一个手动清理口子——什么时候清、清多久，人说了算。
    """
    from sqlalchemy import select

    from .evidence import purge_trash, trash_dir
    from .models import Evidence

    init_db()
    if args.list:
        with session_scope() as s:
            rows = list(
                s.scalars(
                    select(Evidence)
                    .where(Evidence.deleted_at.is_not(None))
                    .order_by(Evidence.deleted_at.desc())
                    .limit(args.limit)
                )
            )
            items = [(r.id, r.kind, r.size, r.deleted_at, r.deleted_by, r.delete_reason, Path(r.path).name) for r in rows]
        if not items:
            print("回收站是空的。")
            return 0
        print(f"{BOLD}回收站{RESET}（最近 {len(items)} 条，文件在 {trash_dir()}）\n")
        for eid, kind, size, when, by, reason, name in items:
            stamp = when.strftime("%Y-%m-%d %H:%M") if when else "—"
            print(f"  #{eid:<5} {kind:<14} {size / 1024:>8.1f} KB  {stamp}  {by or '—'}  {reason or '—'}")
            print(f"         {DIM}{name}{RESET}")
        return 0

    days = args.purge_days
    if days is None:
        print("用法：silver-sentinel trash --list   查看回收站")
        print("      silver-sentinel trash --purge-days 30   清掉 30 天前的文件（记录保留）")
        return 1
    result = purge_trash(older_than_days=days)
    print(
        f"{GRN}已清理回收站{RESET}：删除 {result['removed']} 个文件，"
        f"释放 {result['freed_bytes'] / 1024 / 1024:.1f} MB"
        f"（只删 {days} 天前的文件；数据库里的删除记录永久保留）"
    )
    return 0


def cmd_dismiss(args) -> int:
    """人工排除：把一条资产从自动盯防里摘出来，并留下判断依据。

    为什么需要它：任何人在生产环境上手试一次（导入演示 APK、贴一条公开
    通报里的样例域名），那条记录就会永久留在库里并参与评分。没有人工
    排除的口子，示例数据会一直排在高危列表第一位，把真线索挤下去。
    """
    from .models import TIER_DISMISSED

    init_db()
    with session_scope() as s:
        asset = s.get(Asset, args.asset_id)
        if asset is None:
            print(f"没有 id={args.asset_id} 的资产")
            return 1
        asset.tier = TIER_DISMISSED
        asset.reviewed_by = args.by
        asset.dismiss_reason = args.reason[:200]
        meta = dict(asset.meta or {})
        meta["scoring_exempt"] = True
        asset.meta = meta
        print(
            f"已排除 #{asset.id} {asset.value[:60]}（原分级 {asset.score:.1f}，"
            f"理由：{args.reason}）。后续重评不会把它拉回盯防。"
        )
    return 0


def cmd_rules(args) -> int:
    rs = load_ruleset()
    print(f"规则集 v{rs.version}，共 {len(rs.rules)} 条\n")
    for rule in rs.rules:
        print(f"  {rule.id:<10} {rule.category:<14} {rule.weight:>4.0f}  {rule.title}")
    print(f"\n阈值：{rs.thresholds}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from . import webauth
    from .logsetup import setup_logging

    init_db()
    setup_logging()
    host = args.host or settings.web_host
    port = args.port or settings.web_port

    password = webauth.ensure_password(host)
    if password:
        loopback = host in ("127.0.0.1", "localhost", "::1")
        print(f"访问口令：{password}")
        print(f"口令文件：{webauth._password_file()}（0600）")  # noqa: SLF001
        if not loopback:
            print(f"控制台：http://{host}:{port}/  首次打开需输入上面的口令")
    elif not (args.host or settings.web_host) == "127.0.0.1":
        print("警告：对外监听但未设置口令，已拒绝启动。请设 SILVER_WEB_PASSWORD。")
        return 1

    uvicorn.run("silver_sentinel.api:app", host=host, port=port, reload=args.reload)
    return 0


def cmd_health(args) -> int:  # noqa: ARG001
    from .analyzers import llm

    init_db()
    info = {
        "data_dir": str(settings.data_dir),
        "db_url": settings.db_url,
        "network": settings.allow_network,
        "llm": llm.status(),
        "rules": len(load_ruleset().rules),
        "capabilities": settings.capability_report(),
    }
    try:
        from .worker import capture_queue_health

        info["capture"] = capture_queue_health()
    except Exception as exc:  # noqa: BLE001
        info["capture"] = {"error": str(exc)}
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def cmd_doctor(args) -> int:
    """外部看门狗自检：常驻进程是不是真的还在动。

    只看两件事故前兆：
    1. `heartbeat.json` 多久没更新（supervisor 线程每分钟写一次）；
    2. 取证队列是否 starved（有活、没到期任务、也没在跑）。

    进程还活着但调度线程卡死时，HTTP 探活和界面全都正常，只有这两个指标
    会先掉下来。退出码 1 表示该重启了，部署脚本的 timer 直接据此处理。
    """
    import time as _time

    from .worker import capture_queue_health, heartbeat_file

    result: dict = {"ok": True, "problems": []}
    payload: dict = {}
    path = heartbeat_file()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        age = round(_time.time() - float(payload.get("ts") or 0), 1)
        result["heartbeat"] = {
            "path": str(path),
            "age_s": age,
            "pid": payload.get("pid"),
            "version": payload.get("version"),
            "threads": payload.get("threads"),
        }
        if age > args.max_age:
            result["problems"].append(f"心跳文件已 {age:.0f} 秒未更新（阈值 {args.max_age}s）")
    except FileNotFoundError:
        result["heartbeat"] = {"path": str(path), "age_s": None}
        result["problems"].append("没有心跳文件，服务可能从未成功启动")
    except Exception as exc:  # noqa: BLE001
        result["heartbeat"] = {"path": str(path), "error": str(exc)}
        result["problems"].append(f"心跳文件读不出来：{exc}")

    try:
        # 不调 init_db：看门狗每 2 分钟跑一次，迁移语句会短暂拿写锁，
        # 与正在取证的服务抢锁只会制造抖动。表结构由服务启动时保证。
        queue = capture_queue_health()
        result["capture"] = queue
        if queue.get("starved"):
            result["problems"].append(
                f"有 {queue.get('pending_assets')} 个待取证资产，但队列里没有到期任务"
            )
        if (queue.get("worker_heartbeat_age_s") or 0) > args.max_age:
            result["problems"].append(
                f"取证线程心跳已停 {queue.get('worker_heartbeat_age_s')} 秒"
            )
    except Exception as exc:  # noqa: BLE001
        result["capture"] = {"error": str(exc)}
        result["problems"].append(f"读队列失败：{exc}")

    # 发现侧：只把「引擎没在跑」算故障。CT 日志落后是产能问题，
    # 重启解决不了反而丢游标，所以只记录、不触发重启。
    discover = payload.get("discover") if isinstance(payload, dict) else None
    if discover:
        result["discover"] = discover
        if discover.get("running") is False:
            result["problems"].append("发现引擎未运行")
        elif (discover.get("lag") or 0) > 300_000:
            result["discover_warning"] = (
                f"CT 日志落后 {discover['lag']} 条，发现产能可能不足（不触发重启）"
            )

    # 备案链路：它是最容易「悄悄死掉」的一环——服务没起、地址没配，
    # 查询全部返回 unknown，而外观上一切正常。这里只报警、不触发重启
    # （重启解决不了 docker 容器没起，只会白白打断取证）。
    try:
        from .enrich.icp import get_icp

        st = get_icp().status()
        result["icp"] = {
            "enabled": st.get("enabled"),
            "ready": settings.icp_ready,
            "available": st.get("available"),
            "last_error": st.get("last_error"),
            "cache_days": st.get("cache_days"),
        }
        if settings.icp_enabled and not settings.icp_ready:
            result["icp_warning"] = (
                "备案查询未配置（SILVER_ICP_API 为空）：冒充判定的备案号核验不可用"
            )
        elif st.get("available") is False:
            result["icp_warning"] = f"备案服务不可达：{st.get('last_error') or '探测失败'}"
    except Exception as exc:  # noqa: BLE001
        result["icp"] = {"error": str(exc)[:160]}

    result["ok"] = not result["problems"]
    if args.quiet and result["ok"]:
        return 0
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


def cmd_whitelist(args) -> int:
    """白名单自检：规模、某个域名是不是政府/媒体、机构对应的官方域名。"""
    from .whitelist import get_whitelist

    wl = get_whitelist()
    if args.check:
        rows = [
            {
                "host": h,
                "government": wl.is_government(h),
                "media": wl.is_media(h),
                "agency_domains": wl.agency_domains(h),
            }
            for h in args.check
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(json.dumps(wl.stats(), ensure_ascii=False, indent=2))
    return 0


def cmd_claim(args) -> int:
    """对一条 URL / 一段 HTML 做「自称与冒充」分析。

    这是排查误报最快的入口：不用跑完整流水线，直接看它自称了谁、
    官方域名是什么、判定落在哪一档。
    """
    from .claim import analyze_html, analyze_text

    if args.html_file:
        html = open(args.html_file, encoding="utf-8", errors="ignore").read()
        report = analyze_html(html, args.host or "")
    elif args.text:
        report = analyze_text(args.text, args.host or "", title=args.title or "")
    elif args.url:
        from urllib.parse import urlsplit

        from .collectors.http import HttpClient

        html = HttpClient().get_text(args.url) or ""
        host = args.host or (urlsplit(args.url).hostname or "")
        report = analyze_html(html, host)
    else:
        print(json.dumps({"ok": False, "error": "需要 url / --text / --html-file 之一"},
                         ensure_ascii=False))
        return 2
    print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_purpose(args) -> int:
    """分析站点用途：客服/论坛/电商/企业/门户/落地页/分发页。

    这是排查「为什么这个站排到前面」最快的入口。它不判风险，只回答
    「这个站是干什么的」——客服站和论坛天然信息量大、行业词多，
    词库分会很高，但它们不是目标。
    """
    from .features import extract
    from .purpose import analyze, model_info

    facts: dict = {}
    html = text = ""
    requests: list = []
    forms: list = []
    tls: dict = {}
    apk_links: list = []
    host = args.host or ""

    if args.asset_id:

        from .db import session_scope
        from .models import Asset
        from .scoring.reassess import _purpose_from_evidence

        with session_scope() as session:
            asset = session.get(Asset, args.asset_id)
            if asset is None:
                print(json.dumps({"ok": False, "error": "资产不存在"}, ensure_ascii=False))
                return 2
            facts = dict((asset.meta or {}).get("facts") or {})
            host = host or asset.normalized or asset.value
            if facts.get("purpose"):
                print(json.dumps({"ok": True, "host": host, "source": "stored",
                                  "purpose": facts["purpose"]}, ensure_ascii=False, indent=2))
                return 0
            computed = _purpose_from_evidence(session, asset)
            if not computed:
                print(json.dumps({"ok": False, "error": "该资产没有可用的页面证据"}, ensure_ascii=False))
                return 1
            feats_dict, purpose_dict = computed
            print(json.dumps({"ok": True, "host": host, "source": "evidence",
                              "purpose": purpose_dict, "hints": feats_dict.get("hints")},
                             ensure_ascii=False, indent=2))
            return 0

    if args.html_file:
        html = open(args.html_file, encoding="utf-8", errors="ignore").read()
        text = args.text or ""
        if not text:
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                text = soup.get_text("\n")
            except Exception:  # noqa: BLE001
                text = ""
    elif args.url:
        from urllib.parse import urlsplit

        from .sandbox.web import get_web_sandbox

        url = args.url if args.url.startswith("http") else f"https://{args.url}"
        obs = get_web_sandbox().observe(url, timeout=args.timeout)
        if not (obs.html or obs.text):
            print(json.dumps({"ok": False, "error": obs.error or "抓取失败"}, ensure_ascii=False))
            return 1
        html, text = obs.html, obs.text
        requests, forms, tls, apk_links = obs.requests, obs.forms, obs.tls, obs.apk_links
        host = host or (urlsplit(obs.final_url or url).hostname or "")
        if html and "claim" not in facts:
            try:
                from .claim import analyze_html

                facts["claim"] = analyze_html(html, host).as_dict()
            except Exception:  # noqa: BLE001
                pass
    else:
        print(json.dumps({"ok": False, "error": "需要 url / --html-file / --asset-id 之一"},
                         ensure_ascii=False))
        return 2

    bundle = extract(url=f"https://{host}/" if host else "", html=html, text=text,
                     facts=facts, requests=requests, forms=forms, tls=tls, apk_links=apk_links)
    result = analyze(bundle, host=host, facts=facts, use_model=not args.no_model)
    out = {
        "ok": True,
        "host": host,
        "purpose": result.as_dict(),
        "top_features": {
            k: round(v, 2)
            for k, v in sorted(bundle.values.items(), key=lambda kv: abs(kv[1]), reverse=True)[:12]
            if v
        },
        "hints": bundle.hints,
        "model": model_info(),
        "text_len": int(bundle.values.get("text_len", 0)),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_model(args) -> int:
    """用途模型的查看 / 训练 / 评估。训练走 tools/train_purpose.py。"""
    from .purpose import model_info

    if args.action == "status":
        info = model_info()
        info["rule_baseline"] = "始终可用（模型缺失时自动接管）"
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0 if info.get("available") else 1

    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    script = _Path(__file__).resolve().parents[2] / "tools" / "train_purpose.py"
    if not script.exists():
        print(json.dumps({"ok": False, "error": f"找不到训练脚本 {script}"}, ensure_ascii=False))
        return 2
    cmd = [_sys.executable, str(script)]
    if args.data:
        cmd += ["--data", args.data]
    if args.min_class:
        cmd += ["--min-class", str(args.min_class)]
    if args.action == "train":
        if args.out:
            cmd += ["--out", args.out]
        if args.report:
            cmd += ["--report", args.report]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    print(proc.stdout)
    if proc.stderr.strip():
        print(proc.stderr[-2000:], file=_sys.stderr)
    return proc.returncode


def cmd_brief(args) -> int:
    """一段时间内的侦查 / 取证态势。

    回答的是运维最关心的一句话：「过去一天，这台机器到底干了什么」。
    分开看「发现供给」和「取证吞吐」——两者任一是 0，都说明链路断了，
    但断的位置不同，处理方式也不同。
    """
    from datetime import timedelta

    from sqlalchemy import func, select

    from .db import init_db
    from .domain import utcnow as _utcnow
    from .models import CaptureTask, Evidence

    # 新装或数据目录被清过时，先建表：brief 是运维第一入口，
    # 不该因为「表还没建」直接抛 sqlite3 异常。
    init_db()

    hours = max(1, args.hours)
    since = _utcnow() - timedelta(hours=hours)

    with session_scope() as s:
        new_assets = s.scalar(select(func.count(Asset.id)).where(Asset.first_seen >= since)) or 0
        by_source = dict(
            s.execute(
                select(Asset.discovery_source, func.count(Asset.id))
                .where(Asset.first_seen >= since)
                .group_by(Asset.discovery_source)
                .order_by(func.count(Asset.id).desc())
            ).all()
        )
        siblings = s.scalar(
            select(func.count(Asset.id)).where(
                Asset.first_seen >= since, Asset.discovery_source == "ct_san"
            )
        ) or 0
        captured = s.scalar(
            select(func.count(CaptureTask.id)).where(
                CaptureTask.state == "done", CaptureTask.finished_at >= since
            )
        ) or 0
        failed = s.scalar(
            select(func.count(CaptureTask.id)).where(
                CaptureTask.state == "failed", CaptureTask.finished_at >= since
            )
        ) or 0
        # 冷档填谷的失败不算异常：cold 池里大量是「签了还没建站」的域名，
        # 填谷就是在替它们占位、等上线。真正要看的是真线索的失败率。
        failed_by_reason = dict(
            s.execute(
                select(CaptureTask.reason, func.count(CaptureTask.id))
                .where(CaptureTask.state == "failed", CaptureTask.finished_at >= since)
                .group_by(CaptureTask.reason)
            ).all()
        )
        evidence = s.scalar(
            select(func.count(Evidence.id)).where(Evidence.captured_at >= since)
        ) or 0
        watch_new = s.scalar(
            select(func.count(Asset.id)).where(
                Asset.first_seen >= since, Asset.tier.in_(("watch", "confirmed"))
            )
        ) or 0
        pending = s.scalar(
            select(func.count(Asset.id)).where(
                Asset.capture_state == "pending",
                Asset.tier.in_(("candidate", "watch", "confirmed")),
            )
        ) or 0
        # 用途分布：解释「新增很多但 watch 很少」。meta 是 JSON，跨库解析
        # 交给 Python——SQLite 的 json_extract 在 Postgres 上不通用。
        purpose_meta = list(
            s.scalars(select(Asset.meta).where(Asset.first_seen >= since)).all()
        )

    total = captured + failed
    rate = f"{captured / total * 100:.1f}%" if total else "—"
    src = "  ".join(f"{k or '未知'} {v}" for k, v in list(by_source.items())[:6])
    cold_failed = failed_by_reason.get("cold-fill", 0)
    real_failed = failed - cold_failed
    fail_note = f"失败 {failed}"
    if cold_failed:
        fail_note += f"（填谷 {cold_failed}）"

    print(f"{BOLD}侦查态势{RESET}（近 {hours} 小时）")
    print(f"  新资产    {new_assets:>6}   {DIM}{src}{RESET}")
    print(f"  证书兄弟  {siblings:>6}   {DIM}同证书扩散（站群关联）{RESET}")
    print(f"  取证完成  {captured:>6}   {fail_note}（成功率 {rate}）")
    print(f"  新增证据  {evidence:>6}")
    print(f"  新增盯防  {watch_new:>6}")
    print(f"  待取证    {pending:>6}   {DIM}队列里还排着的资产{RESET}")

    purpose_counts: dict[str, int] = {}
    suppressed_n = 0
    labeled = 0
    for meta in purpose_meta:
        purpose = ((meta or {}).get("facts") or {}).get("purpose") if isinstance(meta, dict) else None
        if not isinstance(purpose, dict):
            continue
        name = str(purpose.get("purpose") or "unknown")
        labeled += 1
        purpose_counts[name] = purpose_counts.get(name, 0) + 1
        if purpose.get("suppressed"):
            suppressed_n += 1
    if purpose_counts:
        from .purpose import PURPOSE_LABELS

        order = ("customer_service", "forum", "ecommerce", "corporate", "portal",
                 "app_dist", "landing", "unknown")
        parts = [
            f"{PURPOSE_LABELS.get(k, k)} {purpose_counts[k]}"
            for k in order if purpose_counts.get(k)
        ]
        print(f"  用途分布  {DIM}{'  '.join(parts)}{RESET}")
        print(f"  用途降级  {suppressed_n:>6}   {DIM}客服/论坛/电商/企业不占高危队列{RESET}")

    problems = []
    if not new_assets and not pending:
        problems.append("没有任何新资产——发现链路可能停了")
    if not captured and pending:
        problems.append("有待取证资产但没有完成——取证线程可能卡住")
    if real_failed > max(20, captured):
        problems.append("真线索的失败数超过完成数——目标侧在集体拒连，检查出口 IP 是否被拉黑")
    # 闸门过宽会静默吃掉召回：一段时间里绝大多数新资产都被判成「非目标」，
    # 要么是真的在抓客服站（词库召回跑偏），要么是闸门误判（该关掉查）。
    if labeled >= 50 and suppressed_n / labeled >= 0.75:
        problems.append(
            f"用途闸门降级比例 {suppressed_n / labeled:.0%}（{suppressed_n}/{labeled}）——"
            "检查是否在大量收客服/论坛站，或用 SILVER_PURPOSE_SUPPRESS=0 临时关闸"
        )
    for item in problems:
        print(f"  {YEL}⚠ {item}{RESET}")
    return 0 if not problems else 1


def cmd_rescore(args) -> int:
    """用已取到的证据重算评分。

    线上有一批资产是在「读不到正文」的版本下打的分：证据仓里明明有
    page_text，评分只用了域名。这条命令把它们捞回来重判。
    """
    from .scoring.reassess import rescore_by_id, rescore_many

    init_db()
    if args.asset_id:
        result = rescore_by_id(args.asset_id, trigger="cli")
    else:
        result = rescore_many(limit=args.limit, only_with_text=not args.all, retier=args.retier)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 发现


def _reconcile(args) -> int:
    """按当前词库复算存量资产，把旧版子串匹配的误报降级。

    为什么要做这一步：词库精度升级只影响「新发现」，已经躺在库里的
    2,512 个资产仍然占着候选池与富化队列。默认只报告不写库（--apply 才改）。
    """
    from sqlalchemy import select

    from .discover.keywords import get_library
    from .domain import utcnow
    from .models import TIER_DISMISSED
    from .normalize import collapse_host, is_shared_infra

    init_db()
    lib = get_library()
    with session_scope() as session:
        rows = list(
            session.scalars(
                select(Asset).where(Asset.kind == "domain").order_by(Asset.score.desc())
            ).all()
        )
        existing = {a.normalized for a in rows}

        stats = {"total": len(rows), "no_keyword": 0, "shared_infra": 0, "subdomain_of_asset": 0,
                 "kept": 0}
        samples: dict[str, list[str]] = {"no_keyword": [], "shared_infra": [], "subdomain_of_asset": []}
        plan: list[tuple[int, str]] = []
        for asset in rows:
            value = (asset.normalized or asset.value).lower()
            if is_shared_infra(value):
                stats["shared_infra"] += 1
                plan.append((asset.id, "共享基础设施：平台分配的随机主机名，不构成目标"))
                samples["shared_infra"].append(value)
                continue
            # 只对「靠词库命中进来的」做复核。DNS 探测与人工导入本来就可能
            # 不含关键词（随机域名），拿词库去否定它们会误杀真线索。
            if asset.discovery_source not in ("ct_poll", "certstream"):
                stats["kept"] += 1
                continue
            if not lib.match_domain(value).hits:
                stats["no_keyword"] += 1
                plan.append((asset.id, "词库精度升级：旧版子串匹配误报，不含任何有效词根"))
                samples["no_keyword"].append(value)
                continue
            apex = collapse_host(value)
            if apex and apex != value and apex in existing:
                stats["subdomain_of_asset"] += 1
                plan.append((asset.id, f"同一注册域已有资产：{apex}"))
                samples["subdomain_of_asset"].append(value)
                continue
            stats["kept"] += 1

        if args.apply:
            touched = 0
            for asset_id, reason in plan:
                asset = session.get(Asset, asset_id)
                if asset is None or asset.tier == TIER_DISMISSED:
                    continue
                asset.tier = TIER_DISMISSED
                asset.dismiss_reason = reason[:200]
                asset.last_seen = utcnow()
                # 子域降级前，先把主机名记到主资产上——证据不能因为归并而丢
                if reason.startswith("同一注册域"):
                    apex = collapse_host((asset.normalized or asset.value).lower())
                    host_asset = session.scalar(
                        select(Asset).where(Asset.kind == "domain", Asset.normalized == apex)
                    )
                    if host_asset is not None:
                        meta = dict(host_asset.meta or {})
                        hosts = meta.get("hosts") or []
                        value = (asset.normalized or asset.value).lower()
                        if value not in hosts and len(hosts) < 30:
                            meta["hosts"] = hosts + [value]
                            host_asset.meta = meta
                touched += 1
            stats["applied"] = touched

    for key in ("no_keyword", "shared_infra", "subdomain_of_asset"):
        stats[f"{key}_sample"] = samples[key][:8]
    print(json.dumps({"ok": True, "dry_run": not args.apply, **stats}, ensure_ascii=False, indent=2))
    return 0


def cmd_discover(args) -> int:
    """发现引擎的运维入口。

    长期跑用 `--foreground`（或直接交给 serve 的调度器）；
    临时补漏用 `inject` / `search`，不需要常驻进程。
    """
    from .discover.engine import get_engine

    init_db()

    if args.action == "status":
        print(json.dumps(get_engine().status(), ensure_ascii=False, indent=2))
        return 0

    if args.action == "words":
        from collections import defaultdict

        from .discover.keywords import get_library

        lib = get_library()
        stats = lib.stats()
        grouped: dict[str, list[str]] = defaultdict(list)
        for term in lib.terms:
            grouped[term.cluster].append(term.text)
        print(f"{BOLD}词库{RESET}：{stats['terms']} 个词根 · {stats['pinyin_terms']} 条拼音变体 · "
              f"{len(grouped)} 个语义簇")
        for name, words in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            sample = "、".join(words[:20])
            more = "" if len(words) <= 20 else f" …（共 {len(words)}）"
            print(f"\n  {CYA}{name}{RESET}  {DIM}{sample}{more}{RESET}")
        return 0

    if args.action == "inject":
        values = list(args.values or [])
        if args.file:
            values += [
                line.strip()
                for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        if not values:
            print("没有可导入的值。用位置参数或 --file。", file=sys.stderr)
            return 2
        print(json.dumps(get_engine().inject(values, note=args.note or ""), ensure_ascii=False))
        return 0

    if args.action == "reconcile":
        return _reconcile(args)

    if args.action == "search":
        terms = list(args.values or [])
        if not terms:
            print("需要至少一个词根，例如：discover search 国惠 中科", file=sys.stderr)
            return 2
        print(json.dumps(get_engine().search_history(terms), ensure_ascii=False))
        return 0

    # run / foreground
    engine = get_engine()
    engine.start()
    if not engine.status().get("running"):
        print(f"{YEL}发现引擎未启动{RESET}：检查 SILVER_DISCOVER_ENABLED 与 SILVER_ALLOW_NETWORK", file=sys.stderr)
        return 1

    duration = args.minutes * 60 if args.minutes else 0
    started = time.monotonic()
    print(f"{GRN}发现引擎运行中{RESET}，{'常驻，Ctrl-C 停止' if not duration else f'{args.minutes} 分钟后自动停止'}")
    try:
        while True:
            time.sleep(15)
            st = engine.status()
            s = st["stats"]
            print(
                f"  {DIM}{int(time.monotonic() - started):>5}s{RESET} "
                f"证书 {s.get('certs_seen', 0)} → 命中 {s.get('keyword_hits', 0)} "
                f"→ 入库 {s.get('created', 0)}  待落库 {st.get('pending', 0)}"
            )
            if duration and time.monotonic() - started >= duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
    print(json.dumps(engine.status(), ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 流水线


def cmd_cycle(args) -> int:
    from .pipeline import run_cycle

    init_db()
    result = run_cycle(
        scan_limit=args.scan_limit,
        enrich_limit=args.enrich,
        rebuild_graph=not args.no_graph,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        mark = f"{GRN}完成{RESET}" if result.get("ok") else f"{RED}失败{RESET}"
        print(f"{BOLD}一轮流水线{mark}")
        print(f"  研判 {result.get('scanned', 0)}  富化 {result.get('enriched', 0)}  "
              f"图边 {result.get('graph_edges', 0)}  团伙 {result.get('campaigns', {})}  "
              f"衰减 {result.get('decayed', 0)}  耗时 {result.get('elapsed', 0):.1f}s")
        if result.get("error"):
            print(f"  {RED}{result['error']}{RESET}")
    return 0 if result.get("ok") else 1


def cmd_graph(args) -> int:
    from .graph.build import build_graph
    from .graph.community import sync_campaigns
    from .graph.store import get_graph

    init_db()
    if args.action == "stats":
        print(json.dumps(get_graph().stats(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "build":
        print(json.dumps(build_graph(limit=args.limit), ensure_ascii=False, indent=2))
        return 0
    if args.action == "communities":
        print(json.dumps(sync_campaigns(), ensure_ascii=False, indent=2))
        return 0
    # rebuild = build + 归并
    built = build_graph(limit=args.limit)
    merged = sync_campaigns()
    print(json.dumps({"graph": built, "campaigns": merged}, ensure_ascii=False, indent=2))
    return 0


def cmd_enrich(args) -> int:
    from .pipeline import enrich_asset, probe_web

    init_db()
    if args.probe:
        result = probe_web(args.asset_id)
    else:
        result = enrich_asset(args.asset_id, with_sandbox=args.sandbox)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", True) else 1


def cmd_icp(args) -> int:
    """批量备案回填。

    为什么单独做一条命令
    --------------------
    ICP 查询慢（验证码识别 1-30 秒不等）且对频率敏感，塞进每轮调度会把
    整条富化队列拖住。正确的做法是离线补历史：服务照常跑，这条命令在
    后台按分数从高到低把存量补齐，结果直接进缓存，服务下次研判自动复用。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from sqlalchemy import select

    from .domain import utcnow
    from .enrich.icp import get_icp
    from .normalize import collapse_host

    init_db()
    if getattr(args, "license", ""):
        # 按备案号反查：这是抓「伪造备案」的正确姿势。
        # 查域名只能得到「有/没有」，查备案号能直接得到「这个号属于谁」。
        out = get_icp().lookup_license(args.license)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0 if out.get("status") in ("registered", "unregistered") else 1
    if not settings.icp_ready:
        print(json.dumps({"ok": False, "error": "未配置 SILVER_ICP_API，先起 ICP_Query 再填地址"},
                         ensure_ascii=False, indent=2))
        return 2

    tiers = tuple(args.tier.split(",")) if args.tier else tuple(settings.icp_tier_set)
    with session_scope() as session:
        stmt = (
            select(Asset)
            .where(Asset.kind.in_(("domain", "url")), Asset.icp_status == args.status)
            .order_by(Asset.score.desc())
            .limit(args.limit)
        )
        if tiers:
            stmt = stmt.where(Asset.tier.in_(tiers))
        rows = list(session.scalars(stmt).all())
        pairs = [(a.id, collapse_host(a.normalized or a.value)) for a in rows]
        # 一次性把「注册域 → 资产 id」建好：按域名再回表扫全库是 O(n²)，
        # 两千多个资产就要几十万次行读，实战里会卡住。
        by_domain: dict[str, list[int]] = {}
        for asset in session.scalars(
            select(Asset).where(Asset.kind.in_(("domain", "url")))
        ).all():
            key = collapse_host(asset.normalized or asset.value)
            if key:
                by_domain.setdefault(key, []).append(asset.id)

    targets = list(dict.fromkeys(d for _id, d in pairs if d))
    if not targets:
        print(json.dumps({"ok": True, "targets": 0, "note": "没有待查目标"}, ensure_ascii=False))
        return 0

    client = get_icp()
    started = time.time()
    done = 0
    tally: dict[str, int] = {}
    listed: list[dict[str, str]] = []
    if args.dry_run:
        print(json.dumps({"ok": True, "dry_run": True, "targets": len(targets),
                          "sample": targets[:10]}, ensure_ascii=False, indent=2))
        return 0

    def work(domain: str):
        return domain, client.lookup(domain, use_cache=not args.refresh)

    pool = ThreadPoolExecutor(max_workers=max(1, args.workers))
    futures = [pool.submit(work, d) for d in targets]
    aborted = ""
    try:
        for fut in as_completed(futures):
            domain, res = fut.result()
            done += 1
            tally[res.status] = tally.get(res.status, 0) + 1
            if res.violation == "listed":
                listed.append({"domain": domain, "title": res.violation_title})
            # 一个注册域可能对应多个主机资产，全部同步，避免下次重复查
            if res.status != "unknown" and args.status == "unknown":
                ids = by_domain.get(domain) or []
                if ids:
                    with session_scope() as session:
                        for asset in session.scalars(
                            select(Asset).where(Asset.id.in_(ids))
                        ).all():
                            asset.icp_status = res.status
                            asset.icp_license = res.license or asset.icp_license
                            asset.icp_entity = res.entity or asset.icp_entity
                            asset.icp_checked_at = utcnow()
                            if res.violation in ("listed", "clean"):
                                asset.icp_violation = res.violation
                                asset.icp_violation_title = res.violation_title
            if done % 10 == 0:
                elapsed = time.time() - started
                print(f"  {done}/{len(targets)}  {elapsed:.0f}s  "
                      f"{done / max(elapsed, 1) * 60:.0f}/min  {tally}", file=sys.stderr)
            # 一旦进入风控冷却，立刻停手。继续打只会把 IP 封得更久。
            remaining = client.status().get("cooldown_remaining", 0)
            if remaining:
                aborted = f"接口疑似风控，已冷却 {remaining} 秒后重试（已处理 {done} 个）"
                print(f"\n{aborted}", file=sys.stderr)
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    print(json.dumps({
        "ok": True,
        "targets": len(targets),
        "elapsed_seconds": round(time.time() - started, 1),
        "results": tally,
        "listed": listed[:50],
        "aborted": aborted,
        "stats": client.stats,
    }, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 证据与副本


def cmd_log(args) -> int:
    from .core.eventlog import EventLog

    init_db()
    if args.action == "verify":
        log_file = EventLog()
        try:
            result = log_file.verify(deep=not args.fast)
        finally:
            log_file.close()
        if result.get("ok"):
            print(f"{GRN}事件日志完好{RESET}：{result.get('checked', 0)} 条，"
                  f"链头 {str(result.get('head', ''))[:16]}…")
            return 0
        print(f"{RED}事件日志异常{RESET}：第 {result.get('broken_at_line')} 行，{result.get('reason')}")
        return 1
    # tail
    log_file = EventLog()
    try:
        for ev in log_file.tail(args.n):
            print(f"#{ev.seq:<8} {ev.ts} {ev.kind:<20} {json.dumps(ev.payload, ensure_ascii=False)[:160]}")
    finally:
        log_file.close()
    return 0


def cmd_replica(args) -> int:
    from .core.replica import get_replica

    init_db()
    replica = get_replica()
    if args.action == "status":
        print(json.dumps(replica.status(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "restore":
        print(json.dumps(replica.restore_events(), ensure_ascii=False, indent=2))
        return 0
    result = replica.run_once(include_db=args.with_db)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", True) else 1




def cmd_vault(args) -> int:
    """加密证据仓：初始化、固化、拉取、校验、导出账本。"""
    from .vault import get_vault

    init_db()
    vault = get_vault()
    action = args.action

    if action == "init":
        existing = vault.keys.path
        if existing.is_file() and not args.force:
            print(f"密钥已存在：{existing}（确需重建请加 --force，旧密文将无法解密）")
            return 1
        key = vault.keys.create(args.passphrase or settings.vault_passphrase)
        print(json.dumps({
            "ok": True,
            "node": vault.node_id,
            "key_file": str(existing),
            "key_id": vault.keys.key_id,
            "key_b64": __import__("base64").b64encode(key).decode(),
            "notice": "请离线备份上方 key_b64；丢失后所有密文不可恢复，泄露则等于证据公开。",
        }, ensure_ascii=False, indent=2))
        return 0

    if action == "status":
        print(json.dumps(vault.status(), ensure_ascii=False, indent=2))
        return 0

    if action == "push":
        result = vault.push(limit=args.limit)
    elif action == "pull":
        result = vault.pull(limit=args.limit)
    elif action == "sync":
        result = vault.sync_once()
    elif action == "verify":
        result = vault.verify(deep=not args.fast)
    elif action == "export":
        if not args.out:
            print("需要 --out 指定导出目录")
            return 2
        result = vault.export_ledger(args.out)
    elif action == "import":
        if not args.src:
            print("需要 --src 指定账本目录")
            return 2
        result = vault.import_ledger(args.src)
    else:
        print(f"未知操作：{action}")
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", True) else 1


def cmd_opsec(args) -> int:
    """出站防护自检：分类、脱敏、当前出口状态。"""
    from .opsec import get_guard, redact_obj, status

    guard = get_guard()
    if args.action == "status":
        print(json.dumps(status(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "check":
        if not args.value:
            print("需要提供 URL")
            return 2
        try:
            kind = guard.preflight(args.value)
            result = {"url": args.value, "class": kind, "proxy": guard.proxy_for(args.value)}
        except Exception as exc:  # noqa: BLE001
            result = {"url": args.value, "blocked": True, "reason": str(exc)}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.action == "redact":
        text = args.value or ""
        print(json.dumps(redact_obj(text), ensure_ascii=False, indent=2))
        return 0
    return 2



def cmd_ops(args) -> int:  # noqa: ARG001
    """一眼看全：能力降级、发现吞吐、待办积压、证据完整性。"""
    from .core.eventlog import EventLog
    from .db import db_stats
    from .discover.engine import get_engine
    from .graph.store import get_graph
    from .models import Campaign

    init_db()
    log_file = EventLog()
    try:
        integrity = log_file.verify(deep=False)
    finally:
        log_file.close()

    with session_scope() as session:
        campaigns = session.query(Campaign).count()

    from . import opsec
    from .vault import VaultError, get_vault

    # 本命令是独立进程：直接调 get_engine() 只会拿到一个刚创建的空引擎。
    # 若要查看常驻服务，设置 SILVER_API_URL 让它去读运行中进程的真实状态。
    live: dict = {}
    api_base = os.environ.get("SILVER_API_URL", "").rstrip("/")
    if api_base:
        import urllib.request

        for name, path in (("discover", "/api/discover/status"), ("vault", "/api/vault")):
            try:
                with urllib.request.urlopen(f"{api_base}{path}", timeout=3) as resp:
                    live[name] = json.loads(resp.read())
            except Exception:  # noqa: BLE001
                pass

    vault_info: dict = {"enabled": settings.vault_enabled}
    if settings.vault_enabled:
        try:
            vault_info = get_vault().status()
        except VaultError as exc:
            vault_info["error"] = str(exc)

    info = {
        "capabilities": settings.capability_report(),
        "db": db_stats(),
        "eventlog": integrity,
        "discover": get_engine().status()["stats"],
        "graph": get_graph().stats(),
        "campaigns": campaigns,
        "opsec": opsec.status(),
        "vault": vault_info,
        "live": live,
        "note": "discover 字段来自本进程；常驻服务状态请设 SILVER_API_URL 或直接请求 /api/discover/status",
    }
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="silver-sentinel", description="银发哨兵 · 涉老诈骗研判工具")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="研判链接/域名/文本")
    p.add_argument("kind", choices=["url", "domain", "text", "miniapp", "account"])
    p.add_argument("value")
    p.add_argument("--text", help="补充上下文（聊天记录、页面文案）")
    p.add_argument("--file", help="APK 路径（kind=apk 时使用）")
    p.add_argument("--channel", help="分发方式：sideload/qr/link/store")
    p.add_argument("--no-llm", action="store_true", help="跳过 LLM，仅用规则")
    p.add_argument("--json", action="store_true", help="输出 JSON")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("apk", help="分析 Android 安装包")
    p.add_argument("path")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_apk)

    p = sub.add_parser("list", help="列出线索")
    p.add_argument("--verdict", choices=list(VERDICT_LABELS))
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("report", help="生成举报材料")
    p.add_argument("asset_id", type=int)
    p.add_argument("--channel", default="12321")
    p.add_argument("--bundle", action="store_true", help="导出多渠道完整包")
    p.add_argument("--out", help="写入文件")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("watch", help="监控目标管理")
    p.add_argument("action", choices=["add", "list", "run"])
    p.add_argument("value", nargs="?")
    p.add_argument("--kind", default="keyword", choices=["keyword", "domain", "brand"])
    p.add_argument("--interval", type=int, default=360)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("verify-chain", help="校验证据链完整性")
    p.add_argument("--asset", type=int)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("trash", help="回收站：列出 / 物理清理（记录永久保留）")
    p.add_argument("--list", action="store_true", help="只看不删")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--purge-days", type=int, default=None, help="清理多少天前的文件（必须显式指定）")
    p.set_defaults(func=cmd_trash)

    p = sub.add_parser("dismiss", help="人工排除：把一条资产移出自动盯防并记录理由")
    p.add_argument("asset_id", type=int)
    p.add_argument("--reason", required=True, help="判断依据（会写进资产记录，供复核）")
    p.add_argument("--by", default="ops", help="操作人标识")
    p.set_defaults(func=cmd_dismiss)

    # ------------------------------------------------------------ 发现
    p = sub.add_parser("discover", help="发现引擎：CT 监控 / 词库 / 注入 / 历史补漏")
    p.add_argument(
        "action",
        choices=["run", "status", "words", "inject", "search", "reconcile"],
        help="run 常驻运行，status 看吞吐，words 看词库覆盖，inject 导入清单，"
             "search 翻 crt.sh 历史，reconcile 按新词库复算存量",
    )
    p.add_argument("values", nargs="*", help="inject 的域名，或 search 的词根")
    p.add_argument("--file", help="从文件批量导入（每行一个域名，# 开头为注释）")
    p.add_argument("--note", help="导入备注，会写进发现流水")
    p.add_argument("--minutes", type=float, default=0, help="run 的时长（分钟），0 为常驻")
    p.add_argument("--apply", action="store_true", help="reconcile 时真正写库（默认只报告）")
    p.set_defaults(func=cmd_discover)

    # ------------------------------------------------------------ 流水线与图
    p = sub.add_parser("cycle", help="跑一轮完整流水线（研判→富化→建图→团伙→衰减）")
    p.add_argument("--scan-limit", type=int, help="本轮最多研判多少个候选")
    p.add_argument("--enrich", type=int, default=40, help="本轮最多富化多少个")
    p.add_argument("--no-graph", action="store_true", help="跳过建图，只跑研判与富化")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_cycle)

    p = sub.add_parser("graph", help="关系图谱：建图 / 统计 / 团伙归并")
    p.add_argument("action", choices=["rebuild", "build", "stats", "communities"])
    p.add_argument("--limit", type=int, default=5000)
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("enrich", help="富化单个资产（备案 / RDAP / 可选沙箱）")
    p.add_argument("asset_id", type=int)
    p.add_argument("--sandbox", action="store_true", help="允许进沙箱跑 APK")
    p.add_argument("--probe", action="store_true", help="跑一次真实网页抓取")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("icp", help="批量备案回填（离线补历史，不阻塞调度）")
    p.add_argument("--limit", type=int, default=2000)
    p.add_argument("--tier", help="只查这些分级，逗号分隔，默认读 SILVER_ICP_TIERS")
    p.add_argument("--status", default="unknown", help="只查该备案状态的资产（默认 unknown）")
    p.add_argument("--workers", type=int, default=2,
                   help="并发数；工信部对突发很敏感，建议 1-2，默认 2")
    p.add_argument("--refresh", action="store_true", help="忽略缓存重新查")
    p.add_argument("--dry-run", action="store_true", help="只列出将查询的域名")
    p.add_argument("--license", default="", help="按备案号反查归属域名（抓伪造备案）")
    p.set_defaults(func=cmd_icp)

    # ------------------------------------------------------------ 证据与副本
    p = sub.add_parser("log", help="事件日志：校验哈希链 / 看末尾")
    p.add_argument("action", choices=["verify", "tail"])
    p.add_argument("-n", type=int, default=20, help="tail 显示条数")
    p.add_argument("--fast", action="store_true", help="只校验链头，不逐条重算")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("replica", help="异地副本：同步 / 状态 / 恢复")
    p.add_argument("action", choices=["sync", "status", "restore"])
    p.add_argument("--with-db", action="store_true", help="同时同步数据库快照")
    p.set_defaults(func=cmd_replica)

    p = sub.add_parser("vault", help="加密证据仓：固化、拉取、校验、导出账本")
    p.add_argument("action", choices=["init", "status", "push", "pull", "sync", "verify", "export", "import"])
    p.add_argument("--out", help="export 的目标目录")
    p.add_argument("--src", help="import 的账本目录")
    p.add_argument("--limit", type=int, default=500, help="单次最多处理多少条")
    p.add_argument("--passphrase", help="init 时用口令派生密钥（留空则随机生成）")
    p.add_argument("--force", action="store_true", help="init 时覆盖已有密钥（危险）")
    p.add_argument("--fast", action="store_true", help="verify 只校验账本链，不解密抽样")
    p.set_defaults(func=cmd_vault)

    p = sub.add_parser("opsec", help="出站防护：状态 / 分类检查 / 脱敏")
    p.add_argument("action", choices=["status", "check", "redact"])
    p.add_argument("value", nargs="?")
    p.set_defaults(func=cmd_opsec)

    p = sub.add_parser("ops", help="运维总览：能力降级、积压、证据完整性")
    p.set_defaults(func=cmd_ops)

    p = sub.add_parser("rules", help="查看规则库")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("health", help="运行状态")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("doctor", help="存活自检（外部看门狗用，异常时退出码 1）")
    p.add_argument("--max-age", type=int, default=300, help="心跳最大允许年龄（秒）")
    p.add_argument("--quiet", action="store_true", help="正常时不输出")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("whitelist", help="政府/媒体白名单自检")
    p.add_argument("--check", nargs="*", metavar="HOST", help="检查这些域名是否在白名单")
    p.set_defaults(func=cmd_whitelist)

    p = sub.add_parser("claim", help="分析页面的「自称」，判定是否冒充政府机构")
    p.add_argument("url", nargs="?", help="要抓取的 URL")
    p.add_argument("--host", help="覆盖判定用的域名")
    p.add_argument("--text", help="直接分析一段文本（不抓页面）")
    p.add_argument("--html-file", help="分析本地 HTML 文件")
    p.add_argument("--title", help="配合 --text 使用的标题")
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("purpose", help="分析站点用途（客服/论坛/电商/企业/门户/落地页）")
    p.add_argument("url", nargs="?", help="站点 URL 或域名")
    p.add_argument("--host", help="覆盖判定用的域名")
    p.add_argument("--html-file", help="分析本地 HTML 文件")
    p.add_argument("--text", help="配合 --html-file 使用的正文")
    p.add_argument("--asset-id", type=int, help="分析库内资产（用已存证据，不联网）")
    p.add_argument("--no-model", action="store_true", help="只用规则基线")
    p.add_argument("--timeout", type=float, default=25.0)
    p.set_defaults(func=cmd_purpose)

    p = sub.add_parser("model", help="用途模型：status / train / eval")
    p.add_argument("action", choices=["status", "train", "eval"])
    p.add_argument("--data", default="", help="数据集路径（默认 data/purpose_seed.jsonl）")
    p.add_argument("--out", default="", help="模型输出路径")
    p.add_argument("--report", default="", help="评估报告输出路径")
    p.add_argument("--min-class", type=int, default=4, help="少于此样本数的类别不参与训练")
    p.add_argument("--timeout", type=float, default=900.0)
    p.set_defaults(func=cmd_model)

    p = sub.add_parser("brief", help="侦查态势：一段时间内的发现 / 取证 / 证据增量")
    p.add_argument("--hours", type=int, default=24, help="统计窗口（小时），默认 24")
    p.set_defaults(func=cmd_brief)

    p = sub.add_parser("rescore", help="用已取证正文重算评分（可批量）")
    p.add_argument("asset_id", nargs="?", type=int, help="只重算这一个资产")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--all", action="store_true", help="连没有正文的资产也重算")
    p.add_argument("--retier", action="store_true", help="允许降档（规则口径变更后重新定级）")
    p.set_defaults(func=cmd_rescore)

    p = sub.add_parser("serve", help="启动 Web 控制台")
    p.add_argument("--host", default="", help="默认取 SILVER_WEB_HOST，未设则 127.0.0.1")
    p.add_argument("--port", type=int, default=0, help="默认取 SILVER_WEB_PORT，未设则 18700")
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"{RED}错误{RESET}：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
