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


def cmd_rules(args) -> int:
    rs = load_ruleset()
    print(f"规则集 v{rs.version}，共 {len(rs.rules)} 条\n")
    for rule in rs.rules:
        print(f"  {rule.id:<10} {rule.category:<14} {rule.weight:>4.0f}  {rule.title}")
    print(f"\n阈值：{rs.thresholds}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    init_db()
    uvicorn.run("silver_sentinel.api:app", host=args.host, port=args.port, reload=args.reload)
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
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 发现


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
    from .vault import VaultError, get_vault

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

    # ------------------------------------------------------------ 发现
    p = sub.add_parser("discover", help="发现引擎：CT 监控 / 词库 / 注入 / 历史补漏")
    p.add_argument(
        "action",
        choices=["run", "status", "words", "inject", "search"],
        help="run 常驻运行，status 看吞吐，words 看词库覆盖，inject 导入清单，search 翻 crt.sh 历史",
    )
    p.add_argument("values", nargs="*", help="inject 的域名，或 search 的词根")
    p.add_argument("--file", help="从文件批量导入（每行一个域名，# 开头为注释）")
    p.add_argument("--note", help="导入备注，会写进发现流水")
    p.add_argument("--minutes", type=float, default=0, help="run 的时长（分钟），0 为常驻")
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

    p = sub.add_parser("serve", help="启动 Web 控制台")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
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
