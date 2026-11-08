"""在生产库上做「只读重评」：新机制会把谁升档、把谁降档，降得对不对。

为什么单独一个工具
------------------
上线前只有种子集（102 条手工标注），它告诉不了你「真实的 4000 条资产会怎样」。
这个工具直接拿生产库当测试集：读取已有证据 → 用当前代码重算 → 输出迁移矩阵，
**不写库、不改档、不建任务**，所以可以在服务运行中随时跑。

它回答三个问题：
1. 迁移矩阵：多少 candidate 会被降档，多少会被升档；
2. 误排除：带「目标形态」（表单/电话/APK/伪造自称）的资产有没有被降档；
3. 降档理由分布：哪一类站贡献了最多降档，逐条可核验。

用法
----
    python3 tools/eval_production.py --out /tmp/eval.jsonl
    python3 tools/eval_production.py --tier candidate --limit 500
    python3 tools/eval_production.py --no-evidence    # 只跑域名级，快

输出末尾打印迁移矩阵与「目标形态被降档」清单，后者必须为空。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from silver_sentinel import triage  # noqa: E402
from silver_sentinel.db import get_session_factory  # noqa: E402
from silver_sentinel.evidence import latest_text_row, read_text  # noqa: E402
from silver_sentinel.models import Asset  # noqa: E402
from silver_sentinel.scoring.reassess import (  # noqa: E402
    _claim_from_evidence,
    _purpose_from_evidence,
    assess_now,
)

TIER_ORDER = ["dismissed", "cold", "candidate", "watch", "confirmed"]
TIER_RANK = {"dismissed": 0, "cold": 1, "candidate": 2, "watch": 3, "confirmed": 4}
# 这些用途是在「风险承接形态」上承载内容，降档即等于放走潜在目标。
# portal 是软排除（只降到 candidate），不算。
TARGET_PURPOSES = {"landing", "app_dist", "unknown"}


def _text_of(session, asset: Asset) -> str:
    row = latest_text_row(session, asset.id)
    return read_text(row, limit=200_000) if row is not None else ""


def _num(v) -> int:
    if isinstance(v, (list, tuple, set, dict)):
        return len(v)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _target_shaped(facts: dict, claim: dict) -> tuple[bool, list[str]]:
    """判断「这个资产是否具备目标形态」。

    只看结构性事实，不看分数：分数是待评估对象，不能拿来做验收标准。
    """
    feats = facts.get("features") or {}
    why: list[str] = []
    if claim.get("verdict") in ("fake_site_id", "fake_icp", "impersonation"):
        why.append(f"claim:{claim['verdict']}")
    if _num(facts.get("apk_links")) > 0:
        why.append("apk")
    if _num(feats.get("tel_inputs")) >= 2:
        why.append("tel_inputs")
    if _num(feats.get("id_inputs")) >= 1:
        why.append("id_inputs")
    return bool(why), why


def _settle(asset: Asset, decision, allow_downgrade: bool) -> str:
    """复现 triage.apply 的落档规则（不写库），否则评估结果会比线上乐观。

    线上只允许升级自动发生；降级要 allow_downgrade（rescore --retier）。
    已排除的是终态，除了命中官方通报，任何流程都不复活它。
    """
    previous = asset.tier or "cold"
    meta = asset.meta or {}
    if previous == "dismissed" and decision.tier != "confirmed":
        return "dismissed"
    first_time = (not meta.get("triaged")) and previous != "confirmed"
    if allow_downgrade and previous != "confirmed" and not asset.reviewed_by:
        return decision.tier
    if first_time or TIER_RANK.get(decision.tier, 0) >= TIER_RANK.get(previous, 0):
        return decision.tier
    return previous


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="", help="只看某个档位，逗号分隔")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-evidence", action="store_true", help="不补算证据（域名级快评）")
    ap.add_argument("--out", default="", help="逐条结果写 JSONL")
    ap.add_argument(
        "--allow-downgrade", action="store_true",
        help="模拟 rescore --retier：允许降档落地（默认只允许升级）",
    )
    args = ap.parse_args()

    tiers = [t.strip() for t in args.tier.split(",") if t.strip()]
    session = get_session_factory()()
    out = open(args.out, "w", encoding="utf-8") if args.out else None

    rows = session.query(Asset).filter(Asset.kind.in_(("domain", "url")))
    if tiers:
        rows = rows.filter(Asset.tier.in_(tiers))
    rows = rows.order_by(Asset.score.desc())
    if args.limit:
        rows = rows.limit(args.limit)

    matrix: Counter = Counter()
    purpose_dist: Counter = Counter()
    downgrade_reasons: Counter = Counter()
    danger: list[dict] = []
    downgraded: list[dict] = []
    upgraded: list[dict] = []
    n = 0

    for asset in rows:
        n += 1
        facts: dict = {}
        claim: dict = {}
        purpose: dict = {}

        if not args.no_evidence:
            c = _claim_from_evidence(session, asset)
            if c:
                claim = c
                facts["claim"] = c
            computed = _purpose_from_evidence(session, asset)
            if computed:
                feats, purpose = computed
                facts.setdefault("features", feats)
                facts["purpose"] = purpose
        else:
            old = (asset.meta or {}).get("facts") or {}
            claim = old.get("claim") or {}
            purpose = old.get("purpose") or {}

        body = "" if args.no_evidence else _text_of(session, asset)
        try:
            assessment, merged = assess_now(asset, facts=facts, text=body)
        except Exception as exc:  # noqa: BLE001 单条失败不中断全量评估
            print(f"  !! {asset.value}: {exc}", file=sys.stderr)
            continue

        decision = triage.decide(asset, facts=merged, verdict=assessment.verdict)
        old_tier = asset.tier or "cold"
        new_tier = _settle(asset, decision, args.allow_downgrade)
        matrix[(old_tier, new_tier)] += 1
        pname = (purpose.get("purpose") or "?") if isinstance(purpose, dict) else "?"
        purpose_dist[pname] += 1

        shaped, why_shaped = _target_shaped(merged, claim if isinstance(claim, dict) else {})
        rec = {
            "value": asset.value,
            "old_tier": old_tier,
            "new_tier": new_tier,
            "old_score": round(float(asset.score or 0), 1),
            "new_score": round(float(assessment.score), 1),
            "verdict": assessment.verdict,
            "purpose": pname,
            "purpose_conf": (purpose.get("confidence") if isinstance(purpose, dict) else None),
            "purpose_src": (purpose.get("source") if isinstance(purpose, dict) else None),
            "claim": (claim.get("verdict") if isinstance(claim, dict) else None),
            "suppressed": bool(isinstance(purpose, dict) and purpose.get("suppressed")),
            "reasons": decision.reasons[:4],
            "target_shaped": why_shaped,
        }
        if out:
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")

        oi, ni = TIER_ORDER.index(old_tier), TIER_ORDER.index(new_tier)
        if ni < oi:
            if shaped:
                danger.append(rec)
            else:
                downgraded.append(rec)
            for r in decision.reasons:
                downgrade_reasons[r.split("：")[0][:24]] += 1
        elif ni > oi:
            upgraded.append(rec)

    if out:
        out.close()

    print(f"\n== 样本 {n} 条 ==")
    print("\n-- 档位迁移（行=原档，列=新档）--")
    header = "        " + "".join(f"{t:>11}" for t in TIER_ORDER)
    print(header)
    for a in TIER_ORDER:
        cells = "".join(f"{matrix.get((a, b), 0):>11}" for b in TIER_ORDER)
        print(f"{a:>8}{cells}")

    print("\n-- 用途分布 --")
    for k, v in purpose_dist.most_common():
        print(f"  {k:<18}{v:>6}")

    print("\n-- 降档理由（前缀）--")
    for k, v in downgrade_reasons.most_common(10):
        print(f"  {k:<26}{v:>6}")

    print(f"\n降档 {len(downgraded)} 条，升档 {len(upgraded)} 条")

    print("\n-- 目标形态却被降档（必须为空）--")
    if not danger:
        print("  （无）")
    for rec in danger[:30]:
        print(f"  ✗ {rec['value']:<40} {rec['old_tier']}->{rec['new_tier']} "
              f"{rec['new_score']} {rec['purpose']} {rec['target_shaped']} {rec['reasons'][:2]}")

    print("\n-- 降档样例（供人工核验）--")
    for rec in downgraded[:25]:
        print(f"  {rec['value']:<40} {rec['old_tier']:>9}->{rec['new_tier']:<9} "
              f"{rec['new_score']:>5} {rec['purpose']:<15} {rec['reasons'][:1]}")

    session.close()
    return 1 if danger else 0


if __name__ == "__main__":
    raise SystemExit(main())
