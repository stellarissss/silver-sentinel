"""命令行入口。

设计成「无服务也能用」：现场排查时，一条命令拿到结论和举报稿，
不需要先起 Web、不需要数据库管理界面。
"""

from __future__ import annotations

import argparse
import json
import sys
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
