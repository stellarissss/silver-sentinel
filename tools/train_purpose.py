"""训练「站点形态」模型：经营型站点 vs 风险承载形态。

为什么是二分类，不是八分类
--------------------------
八分类（客服/论坛/电商/企业/新闻/门户/落地页/分发页）在本规模下落得
准确率 0.54——不是模型不行，是**类别边界本身模糊**：新闻站和行业门户
在结构上几乎同构，论坛和企业站都有多级导航。硬分只会互相吞样本。

业务上真正需要的其实是一个判断：**这个站的形态会不会承载诈骗**。
- 经营型（operational）：客服/论坛/电商/企业/新闻/门户——有长期经营形态，
  页面结构、内容生态、可核验的主体；
- 风险承载（target_shaped）：单页落地、侧载分发——「一个页面劝你做一件事」。
具体是哪一种经营形态，交给规则解释（人能看懂，也能改），不由模型细猜。

用法
----
    python3 tools/train_purpose.py
    python3 tools/train_purpose.py --report docs/25-附录-模型评估.md
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from silver_sentinel.features import FEATURE_NAMES, FEATURE_VERSION  # noqa: E402

POSITIVE = "target_shaped"
NEGATIVE = "operational"
# 形态标签 → 二分类。规则仍保留具体用途名，用于展示与解释。
TARGET_LABELS = frozenset({"landing", "app_dist"})


def load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not row.get("ok"):
            continue
        values = (row.get("features") or {}).get("values") or {}
        if not values:
            continue
        rows.append(row)
    seen: set[str] = set()
    uniq: list[dict] = []
    for row in rows:
        host = row.get("host") or ""
        if host in seen:
            continue
        seen.add(host)
        uniq.append(row)
    return uniq


def vector_of(row: dict) -> list[float]:
    values = (row.get("features") or {}).get("values") or {}
    return [float(values.get(name, 0.0) or 0.0) for name in FEATURE_NAMES]


def _binary_label(raw: str) -> str:
    return POSITIVE if raw in TARGET_LABELS else NEGATIVE


def build_candidates():
    """三个候选模型。小样本上线性模型往往比树模型稳，所以一起比。"""
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    return {
        "logreg": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=0.5)),
        ]),
        "hgb": HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.08, max_leaf_nodes=15,
            min_samples_leaf=5, l2_regularization=1.0, early_stopping=False, random_state=42,
        ),
        "rf": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced", random_state=42,
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="src/silver_sentinel/data/purpose_seed.jsonl")
    ap.add_argument("--out", default="src/silver_sentinel/data/purpose_model.joblib")
    ap.add_argument("--report", default="")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--no-save", action="store_true", help="只评估，不覆盖线上模型")
    args = ap.parse_args()

    data_path = Path(args.data)
    if not data_path.is_absolute():
        data_path = ROOT / data_path
    if not data_path.exists():
        fallback = ROOT / "data" / "purpose_seed.jsonl"
        if fallback.exists():
            data_path = fallback
    rows = load_rows(data_path)
    if len(rows) < 30:
        print(f"样本不足（{len(rows)} 条），先跑 tools/build_purpose_dataset.py")
        return 2

    import numpy as np
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split

    X = np.asarray([vector_of(r) for r in rows], dtype=float)
    y_raw = [r["label"] for r in rows]
    y = np.asarray([_binary_label(label) for label in y_raw])
    counts = Counter(y)
    if min(counts.values()) < 5:
        print(f"二分类样本过少：{dict(counts)}——至少各 5 条，建议各 20 条以上")
        return 2

    min_count = min(counts.values())
    n_splits = int(max(2, min(5, min_count)))
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=7)

    best_name, best_clf, best_score, best_pred = "", None, -1.0, None
    cv_reports: dict[str, float] = {}
    for name, clf in build_candidates().items():
        try:
            pred = cross_val_predict(clf, X, y, cv=cv)
        except Exception as exc:  # noqa: BLE001 某个模型不适用就跳过
            print(f"  {name} 交叉验证失败：{exc}")
            continue
        rep = classification_report(y, pred, output_dict=True, zero_division=0)
        # 主指标用 macro-F1：两类都要好，不能靠「全判经营型」刷准确率
        score = float(rep.get("macro avg", {}).get("f1-score") or 0.0)
        cv_reports[name] = round(score, 4)
        print(f"  {name:<8} CV macro-F1 = {score:.3f}  "
              f"（{POSITIVE} 召回 {rep.get(POSITIVE, {}).get('recall', 0):.2f}）")
        if score > best_score:
            best_name, best_clf, best_score, best_pred = name, clf, score, pred

    if best_clf is None:
        print("没有可用模型")
        return 2
    cv_report = classification_report(y, best_pred, output_dict=True, zero_division=0)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=args.test_size, stratify=y, random_state=42)
    from sklearn.base import clone

    holdout = clone(best_clf).fit(X_tr, y_tr)
    holdout_pred = holdout.predict(X_te)
    holdout_report = classification_report(y_te, holdout_pred, output_dict=True, zero_division=0)

    final = clone(best_clf).fit(X, y)

    metrics = {
        "task": "binary_shape",
        "algorithm": best_name,
        "cv_macro_f1": round(best_score, 4),
        "cv_scores": cv_reports,
        "cv_accuracy": round(float(cv_report.get("accuracy") or 0.0), 4),
        "holdout_accuracy": round(float(holdout_report.get("accuracy") or 0.0), 4),
        "target_recall": round(float(cv_report.get(POSITIVE, {}).get("recall") or 0.0), 3),
        "target_precision": round(float(cv_report.get(POSITIVE, {}).get("precision") or 0.0), 3),
        "operational_recall": round(float(cv_report.get(NEGATIVE, {}).get("recall") or 0.0), 3),
        "operational_precision": round(float(cv_report.get(NEGATIVE, {}).get("precision") or 0.0), 3),
        "shape_counts": dict(Counter(y_raw)),
        "samples": int(len(y)),
        "cv_folds": n_splits,
    }

    # 融合评估：用折外概率复现线上「规则 + 模型」的合成结果。
    # 直接用训练集概率评估会自欺——模型见过那些样本，p_target 会偏低。
    fusion = evaluate_fusion(rows, X, y, best_clf, n_splits)
    metrics["fusion"] = fusion

    payload = {
        "model": final,
        "task": "binary_shape",
        "classes": ["operational", "target_shaped"],
        "positive": POSITIVE,
        "features": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "samples": int(len(y)),
        "metrics": metrics,
    }
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    if args.no_save:
        print(f"\n已评估（{best_name}）：{len(y)} 条样本，未写入模型（--no-save）")
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        import joblib

        joblib.dump(payload, out_path)
        print(f"\n已训练（{best_name}）：{len(y)} 条样本，输出 {out_path}")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print("\n交叉验证分类报告：")
    print(classification_report(y, best_pred, zero_division=0))
    labels_sorted = [NEGATIVE, POSITIVE]
    matrix = confusion_matrix(y, best_pred, labels=labels_sorted)
    print("混淆矩阵（行=真实，列=预测）：")
    for lab, row in zip(labels_sorted, matrix, strict=False):
        print(f"  {lab:<14} " + " ".join(f"{int(v):>6}" for v in row))

    if metrics["target_recall"] < 0.80:
        print(f"\n⚠ 风险承载形态召回 {metrics['target_recall']:.2f} < 0.80——"
              "上线会漏掉落地页，先用规则为主、模型只做否决")
    if metrics["operational_recall"] < 0.85:
        print(f"⚠ 经营型召回 {metrics['operational_recall']:.2f} < 0.85——"
              "会把客服站/论坛漏回高危队列（不致命，但白干）")

    print("\n融合评估（折外概率）：")
    print(f"  纯规则：经营型识别 {fusion['rule_suppressed']}/{fusion['operational_n']} "
          f"({fusion['rule_suppressed'] / max(fusion['operational_n'], 1):.0%})，"
          f"目标形态被误排除 {fusion['rule_danger']}/{fusion['target_n']}")
    print(f"  规则+模型：经营型识别 {fusion['fused_suppressed']}/{fusion['operational_n']} "
          f"({fusion['fused_suppressed'] / max(fusion['operational_n'], 1):.0%})，"
          f"目标形态被误排除 {fusion['fused_danger']}/{fusion['target_n']}")
    for item in fusion["danger_examples"]:
        print(f"    ⚠ {item}")

    if args.report:
        write_report(Path(args.report), metrics, cv_report, labels_sorted, matrix, rows, best_pred)
        print(f"\n评估报告：{args.report}")
    return 0


def evaluate_fusion(rows: list[dict], X, y, clf, n_splits: int) -> dict:
    """用折外概率跑一遍线上融合逻辑，得到「真实上线会长什么样」。"""
    import numpy as np
    from sklearn.base import clone
    from sklearn.model_selection import StratifiedKFold

    from silver_sentinel.features import FeatureBundle
    from silver_sentinel.purpose import (
        NON_TARGET,
        SOFT_NON_TARGET,
        classify_rules,
        decide_suppression,
        fuse,
    )

    target_set = NON_TARGET | SOFT_NON_TARGET
    oof = np.zeros(len(y))
    splitter = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=11)
    for train_idx, test_idx in splitter.split(X, y):
        model = clone(clf).fit(X[train_idx], y[train_idx])
        classes = list(model.classes_)
        oof[test_idx] = model.predict_proba(X[test_idx])[:, classes.index(POSITIVE)]

    stats = {"operational_n": 0, "target_n": 0, "rule_suppressed": 0,
             "rule_danger": 0, "fused_suppressed": 0, "fused_danger": 0,
             "danger_examples": []}
    for row, p_target in zip(rows, oof, strict=False):
        values = (row.get("features") or {}).get("values") or {}
        bundle = FeatureBundle(values={k: float(v or 0) for k, v in values.items()})
        facts = row.get("facts") or {}
        host = row.get("host") or ""
        rule = classify_rules(bundle, host=host,
                              is_government=bool(facts.get("is_government")),
                              is_media=bool(facts.get("is_media")))
        fused = fuse(rule, float(p_target), {POSITIVE: float(p_target),
                                             NEGATIVE: float(1 - p_target)},
                     is_government=bool(facts.get("is_government")),
                     is_media=bool(facts.get("is_media")))
        truth_target = row["label"] in TARGET_LABELS
        rule_sup = rule.purpose in target_set and rule.confidence >= 0.55
        fused_sup = fused.purpose in target_set and fused.confidence >= 0.55
        # decide_suppression 是最后一道闸：硬证据/骗局词/APK/证件表单会让位
        if fused_sup:
            ok, _ = decide_suppression(fused, facts, bundle)
            fused_sup = ok
        if rule_sup:
            ok, _ = decide_suppression(rule, facts, bundle)
            rule_sup = ok

        if truth_target:
            stats["target_n"] += 1
            if rule_sup:
                stats["rule_danger"] += 1
            if fused_sup:
                stats["fused_danger"] += 1
                stats["danger_examples"].append(
                    f"{host}（真值 {row['label']}）被判为 {fused.purpose}，p_target={p_target:.2f}"
                )
        else:
            stats["operational_n"] += 1
            if rule_sup:
                stats["rule_suppressed"] += 1
            if fused_sup:
                stats["fused_suppressed"] += 1
    return stats


def write_report(path: Path, metrics: dict, cv_report: dict, labels: list[str],
                 matrix, rows: list[dict], pred) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 站点形态模型评估（自动生成）",
        "",
        f"- 训练时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- 算法：`{metrics['algorithm']}`（候选：{metrics['cv_scores']}）",
        f"- 样本：{metrics['samples']} 条（{metrics['shape_counts']}）",
        f"- 交叉验证 macro-F1：{metrics['cv_macro_f1']}（{metrics['cv_folds']} 折）",
        f"- 留出集准确率：{metrics['holdout_accuracy']}",
        "",
        "## 关键指标",
        "",
        "| 指标 | 值 | 含义 |",
        "|---|---|---|",
        f"| 风险承载召回 | {metrics['target_recall']:.2f} | 落地页/分发页有没有被认出来 |",
        f"| 风险承载精确 | {metrics['target_precision']:.2f} | 认成落地页的里面有多少真的是 |",
        f"| 经营型召回 | {metrics['operational_recall']:.2f} | 客服/论坛/企业站有没有被正确识别 |",
        f"| 经营型精确 | {metrics['operational_precision']:.2f} | 判成经营型的里面有多少真的是 |",
        "",
        "## 分类报告",
        "",
        "```",
    ]
    for lab in labels:
        m = cv_report.get(lab) or {}
        lines.append(f"{lab:<16} precision={m.get('precision', 0):.2f} "
                     f"recall={m.get('recall', 0):.2f} f1={m.get('f1-score', 0):.2f} "
                     f"n={int(m.get('support', 0))}")
    lines += ["```", "", "## 混淆矩阵", "", "```",
              f"{'':<16}" + " ".join(f"{lab:>14}" for lab in labels)]
    for lab, row in zip(labels, matrix, strict=False):
        lines.append(f"{lab:<16}" + " ".join(f"{int(v):>14}" for v in row))
    lines += ["```", "", "## 逐样本预测（交叉验证）", "",
              "| host | 原始标签 | 二分类真值 | 预测 |", "|---|---|---|---|"]
    for row, p in zip(rows, pred, strict=False):
        flag = " ✓" if p == _binary_label(row["label"]) else " ✗"
        lines.append(f"| {row.get('host', '')} | {row.get('label', '')} | "
                     f"{_binary_label(row['label'])} | {p}{flag} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
