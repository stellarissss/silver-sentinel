"""用途分类：先回答「这个站是干什么的」，再决定「值不值得看」。

和词库的分工
------------
- **词库保广**：发现阶段宁可多收，CT 流每秒几千域名，没有初筛会把富化配额打爆。
- **用途保细**：进队列之后，用「站的形态」把客服站、论坛、电商、企业站挡在
  高危队列之外。它们的信息量往往很大、行业词命中很多，词库分反而更高，
  但它们不是目标。

为什么不是「风险分类器」
------------------------
训练一个「像不像诈骗」的模型需要大量标注，且极易学到「文字短=可疑」这类
伪相关。用途分类不一样：它的类别边界是**结构性的**（有没有购物车、有没有
版块楼层、有没有客服 SDK），弱监督就能学到，而且错了也只会影响排序，
不会把某个站误判成「诈骗」。

融合原则（写死在代码里，不靠调参）
--------------------------------
1. 规则永远生效，模型只是补强；模型缺失时系统照常工作。
2. 规则与模型冲突 → 判 `unknown`，**不做任何排除**。
3. 排除只到 `cold`，永不 `dismissed`：记录留着，claim 硬证据或人工可随时翻案。
4. 有伪造迹象（claim）的站，用途判定一律不生效。
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES, FEATURE_VERSION, FeatureBundle

log = logging.getLogger(__name__)

# 用途词表。顺序即优先级（同分时靠前者胜）。
PURPOSES: tuple[str, ...] = (
    "government",
    "news",
    "customer_service",
    "forum",
    "ecommerce",
    "corporate",
    "portal",
    "app_dist",
    "landing",
    "operational",
    "unknown",
)

PURPOSE_LABELS = {
    "government": "政府机构",
    "news": "新闻媒体",
    "customer_service": "客服系统",
    "forum": "论坛社区",
    "ecommerce": "电商交易",
    "corporate": "企业官网",
    "portal": "行业门户",
    "app_dist": "应用分发",
    "landing": "单页落地",
    "operational": "经营型站点",
    "unknown": "未识别",
}

# 有正当经营形态的站：不占高危队列。降到 cold 而非 dismissed——
# 域名易主、页面改版后仍要能复查。
NON_TARGET = frozenset({"government", "news", "customer_service", "forum", "ecommerce",
                        "corporate", "operational"})
# 门户降一档到 candidate：它可能是正规行业站，也可能是骗子的「政策资讯」外衣。
SOFT_NON_TARGET = frozenset({"portal"})
# 这些用途是诈骗的高发形态，风险判定照常走，不做任何抑制。
RISK_BEARING = frozenset({"landing", "app_dist", "unknown"})

MIN_CONFIDENCE = 0.55          # 规则自身的最低置信
# 模型是二分类「经营型 / 风险承载形态」。它只在两个方向上起作用，
# 而且都是保守方向——不制造新的排除，只否决可能的误排除。
TARGET_VETO = 0.80             # 规则判经营型，但模型认为 p(风险形态) 这么高 → 不排除
OPERATIONAL_CONFIRM = 0.15     # 模型认为 p(风险形态) 这么低 → 给弱规则加一点置信
# 规则确实判不出来、模型又非常确定是经营型时才走这条：它能让大量「结构正常
# 但没有任何用途词」的站不再占用高危队列。门槛压到 0.10，因为这一步会真正
# 产生排除——误排一个落地页的代价比放过十个客服站大得多。
OPERATIONAL_STRONG = 0.10
MODEL_AGREE_BOOST = 0.20       # 规则与模型一致时的置信加成

# 「经营型」的反证。这些词不是风险判据，而是「这个站不可能是正经经营」的
# 结构性反例——博彩、盗播、灰产中介本身就在经营，但绝不能因为「像经营型」
# 被移出队列。线上实测：35 条被模型判为经营型并降档的资产里，混着越南赌场
# （gk88-casino.com.co）、1xbet 镜像、斗鱼体育盗播站群（zc-douyin.cc）。
# 用途判定负责排序，不能负责放行；有反证就不放行。
GATE_VETO = re.compile(
    r"casino|cá\s*c[ượ]c|cá\s*đ[ộo]|nhà\s*cái|nổ\s*hũ|1xbet|betting|sportsbook|"
    r"博彩|赌博|赌场|娱乐城|时时彩|六合彩|彩票投注|棋牌室|彩金|投注|赔率|庄家通吃|"
    r"体育直播|足球直播|篮球直播|无插件|高清直播|免费观看|赛事直播|直播信号|"
    r"直播中|热门直播|免费直播|"
    # 黑产站群命名：xx-douyin.cc / xx-weixin-qq.top。正规企业不会这么起名。
    # 连字符是必要条件，否则会把 qq.com、weixin.qq.com 这类官方域也算进来。
    r"-(?:douyin|weixin|qq|toutiao|kuaishou|baidu|taobao|alipay)(?:-[a-z0-9]{1,6})?"
    r"\.[a-z]{2,6}|"
    r"代办[\u4e00-\u9fff]{0,12}(提取|套现|退保|贷款|提现)|公积金提取|代提公积金|"
    r"征信修复|背债|撸口子|套现|洗白|"
    # 色情/盗版/破解：这类站内容量极大，二分类一样判「经营型」。
    # 线上实测：baidu38.lol（色情导航）、douyin105.xyz（色情社区）、
    # guangxiyijiaguoji.com.cn（星晨电影网盗版影视）、gongxiaoshe88.com（破解软件）。
    r"色情|成人导航|成人色|约炮|约啪|淫穴|自慰|乱伦|偷拍|无码|黄片|里番|AV女优|"
    r"卖淫|嫖娼|援交|福利姬|自拍社区|看片|"
    r"电影网|影片库|影视大全|BT下载|磁力链接|迅雷下载|追剧|"
    r"破解版|破解软件|无限试用|内购破解|私服|外挂",
    re.I,
)

_MODEL_LOCK = threading.Lock()
_MODEL_CACHE: dict[str, Any] = {}


@dataclass(slots=True)
class PurposeResult:
    purpose: str = "unknown"
    confidence: float = 0.0
    source: str = "rule"           # rule | model | fused | none
    reasons: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    model_probs: dict[str, float] = field(default_factory=dict)
    scam_hits: int = 0             # 骗局专属词命中数：用途判定的「一票否决」
    suppressed: bool = False       # 是否据此抑制了风险队列
    suppressed_reason: str = ""

    @property
    def label(self) -> str:
        return PURPOSE_LABELS.get(self.purpose, self.purpose)

    def as_dict(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose,
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "reasons": self.reasons[:6],
            "scores": {k: round(v, 3) for k, v in self.scores.items() if v > 0},
            "model_probs": {k: round(v, 4) for k, v in self.model_probs.items()},
            "scam_hits": self.scam_hits,
            "suppressed": self.suppressed,
            "suppressed_reason": self.suppressed_reason,
        }


# ---------------------------------------------------------------------------
# 规则基线：可解释、可单测、无依赖。模型挂了它还在。
# ---------------------------------------------------------------------------


def _score_rules(
    feats: FeatureBundle,
    *,
    host: str,
    is_government: bool,
    is_media: bool,
) -> dict[str, float]:
    v = feats.values
    nav = v.get("nav_count", 0.0)
    links = v.get("link_count", 0.0)
    text_len = v.get("text_len", 0.0)
    cta_density = v.get("cta_density", 0.0)
    forms = v.get("form_count", 0.0)
    scores: dict[str, float] = {}

    if is_government:
        scores["government"] = 1.0
    if is_media:
        scores["news"] = 0.98

    # 客服：SDK 是最硬的证据；其次是「客服词多 + 导航齐全 + 表单不多」
    cs = 0.0
    cs += min(v.get("cs_sdk_hosts", 0.0), 3.0) * 0.45
    cs += min(v.get("use_cs", 0.0) / 9.0, 1.0) * 0.45
    if nav >= 1 and links >= 25:
        cs += 0.1
    scores["customer_service"] = min(cs, 1.0)

    # 论坛：版块/楼层/回复词 + 多级导航；单页落地页不可能有这些。
    # 域名前缀 bbs./forum. 是最硬的信号之一——很多论坛首页正文很短，
    # 但域名已经说明了形态（实测 bbs.hupu.com 仅靠词命中识别不出来）。
    forum = min(v.get("use_forum", 0.0) / 9.0, 1.0) * 0.8
    # 移动站会把 bbs.hupu.com 跳到 m.hupu.com，前缀判断先剥掉移动前缀
    bare = re.sub(r"^(m|wap|3g|mobile)\.", "", (host or "").lower())
    if re.match(r"^(bbs|forum|club|discuz)\.", bare):
        # 域名已经把形态写在脸上，不需要正文再证明一遍
        forum = max(forum, 0.72)
    if nav >= 2 and links >= 30:
        forum += 0.15
    if v.get("use_corp", 0.0) >= 5 and v.get("use_ecom", 0.0) < 3:
        forum -= 0.1
    scores["forum"] = max(min(forum, 1.0), 0.0)

    # 电商：购物车/商品/订单是最硬的
    ecom = min(v.get("use_ecom", 0.0) / 7.0, 1.0) * 0.85
    if v.get("payment_hosts", 0.0) >= 1:
        ecom += 0.1
    scores["ecommerce"] = min(ecom, 1.0)

    # 企业站：关于我们/解决方案/产品中心 + 导航 + 没有强 CTA
    corp = min(v.get("use_corp", 0.0) / 7.0, 1.0) * 0.8
    if nav >= 1 and links >= 20:
        corp += 0.15
    if cta_density > 3:
        corp -= 0.2
    scores["corporate"] = max(min(corp, 1.0), 0.0)

    # 新闻：责任编辑/来源/记者；白名单已在上面直接给 0.98
    news = min(v.get("use_news", 0.0) / 7.0, 1.0) * 0.75
    if links >= 60 and text_len > 1500:
        news += 0.15
    scores["news"] = max(scores.get("news", 0.0), min(news, 1.0))

    # 门户：频道/专题/政策解读 + 大量链接，但没有购物车
    portal = min(v.get("use_portal", 0.0) / 8.0, 1.0) * 0.7
    if links >= 80 and v.get("use_ecom", 0.0) < 4:
        portal += 0.15
    scores["portal"] = min(portal, 1.0)

    # 应用分发：APK 链接是硬证据
    app = 0.0
    if v.get("apk_links", 0.0) >= 1:
        app += 0.6
    app += min(v.get("use_appdist", 0.0) / 4.0, 1.0) * 0.4
    scores["app_dist"] = min(app, 1.0)

    # 落地页：CTA 密、链接少、没有多级导航；本质是「一个页面劝你做一件事」
    landing = 0.0
    if cta_density >= 1.5:
        landing += 0.4
    if links <= 25 and nav == 0:
        landing += 0.25
    if forms >= 1 and text_len < 3000:
        landing += 0.2
    if v.get("low_text_page", 0.0):
        landing += 0.1
    scores["landing"] = min(landing, 1.0)

    return scores


def classify_rules(
    feats: FeatureBundle,
    *,
    host: str = "",
    is_government: bool = False,
    is_media: bool = False,
) -> PurposeResult:
    scores = _score_rules(feats, host=host, is_government=is_government, is_media=is_media)
    # 按 PURPOSES 顺序取最大，保证同分时优先级稳定
    best, best_score = "unknown", 0.0
    for name in PURPOSES:
        s = scores.get(name, 0.0)
        if s > best_score:
            best, best_score = name, s

    reasons: list[str] = []
    if best != "unknown" and best_score >= MIN_CONFIDENCE:
        reasons = _rule_reasons(best, feats, best_score)
        return PurposeResult(purpose=best, confidence=round(best_score, 3), source="rule",
                             reasons=reasons, scores=scores)
    return PurposeResult(purpose="unknown", confidence=round(best_score, 3), source="rule",
                         reasons=["用途特征不足，交回风险判定"], scores=scores)


def _rule_reasons(purpose: str, feats: FeatureBundle, score: float) -> list[str]:
    v = feats.values
    mapping = {
        "government": "命中政府网站白名单",
        "news": "命中新闻媒体白名单或新闻版式",
        "customer_service": f"客服系统特征（SDK {int(v.get('cs_sdk_hosts', 0))} 个，"
                            f"客服词 {int(v.get('use_cs', 0))} 次）",
        "forum": (
            "域名前缀为 bbs/forum，按论坛处理"
            if int(v.get("use_forum", 0)) == 0
            else f"论坛版式（版块/楼层/回复词 {int(v.get('use_forum', 0))} 个）"
        ),
        "ecommerce": f"电商版式（购物车/商品/订单词 {int(v.get('use_ecom', 0))} 次）",
        "corporate": f"企业站版式（关于我们/解决方案等 {int(v.get('use_corp', 0))} 次）",
        "portal": f"行业门户版式（频道/专题词 {int(v.get('use_portal', 0))} 次）",
        "app_dist": f"应用分发（APK 链接 {int(v.get('apk_links', 0))} 个）",
        "landing": "单页落地（强 CTA、少导航、有表单）",
    }
    base = mapping.get(purpose, purpose)
    return [f"{base}，置信 {score:.2f}"]


# ---------------------------------------------------------------------------
# 模型：缺失即降级，不影响主流程
# ---------------------------------------------------------------------------


def model_path() -> Path:
    override = os.environ.get("SILVER_PURPOSE_MODEL", "").strip()
    if not override:
        try:
            from .config import settings

            override = str(settings.purpose_model or "").strip()
        except Exception:  # noqa: BLE001 配置读不到就用默认路径
            override = ""
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "data" / "purpose_model.joblib"


def load_model(force: bool = False) -> Any | None:
    """加载模型。返回 None 表示「没有可用模型」，调用方走纯规则。"""
    path = model_path()
    key = str(path)
    with _MODEL_LOCK:
        if not force and key in _MODEL_CACHE:
            return _MODEL_CACHE[key]
        model = None
        if path.exists():
            try:
                import joblib

                payload = joblib.load(path)
                if isinstance(payload, dict) and payload.get("features") == FEATURE_NAMES \
                        and payload.get("feature_version") == FEATURE_VERSION:
                    model = payload
                else:
                    log.warning("用途模型特征版本不匹配，已忽略：%s", path)
            except Exception as exc:  # noqa: BLE001
                log.warning("用途模型加载失败 %s：%s", path, exc)
        _MODEL_CACHE[key] = model
        return model


def model_info() -> dict[str, Any]:
    payload = load_model()
    path = model_path()
    if not payload:
        return {"available": False, "path": str(path), "reason": "未训练或版本不匹配"}
    return {
        "available": True,
        "path": str(path),
        "feature_version": payload.get("feature_version"),
        "classes": payload.get("classes"),
        "trained_at": payload.get("trained_at"),
        "metrics": payload.get("metrics") or {},
        "samples": payload.get("samples"),
    }


def _predict_model(payload: dict[str, Any], feats: FeatureBundle) -> tuple[str, float, float, dict[str, float]]:
    clf = payload.get("model")
    classes = list(payload.get("classes") or getattr(clf, "classes_", []))
    if clf is None or not classes:
        return "unknown", 0.0, 0.0, {}
    import numpy as np

    x = np.asarray([feats.vector()], dtype=float)
    proba = clf.predict_proba(x)[0]
    pairs = sorted(zip(classes, proba, strict=False), key=lambda kv: kv[1], reverse=True)
    best, best_p = pairs[0]
    second_p = pairs[1][1] if len(pairs) > 1 else 0.0
    return str(best), float(best_p), float(best_p - second_p), {str(c): float(p) for c, p in pairs}


# ---------------------------------------------------------------------------
# 融合
# ---------------------------------------------------------------------------


def fuse(rule: PurposeResult, p_target: float, probs: dict[str, float], *,
         is_government: bool = False, is_media: bool = False) -> PurposeResult:
    """把「规则结论」与「模型的风险形态概率」合成最终用途。

    纯函数，便于训练脚本用交叉验证的折外概率复现线上融合，避免用训练集
    概率自我验证（那样看什么都好）。
    """
    rule.model_probs = probs
    rule.scores = {**rule.scores, "p_target_shaped": round(p_target, 4)}

    # 白名单是确定性事实，模型不许覆盖
    if is_government or is_media:
        rule.source = "fused"
        return rule

    if rule.purpose in NON_TARGET or rule.purpose in SOFT_NON_TARGET:
        # 规则说「经营型」，但模型强烈认为像落地页：不排除，交回风险判定。
        # 这是模型唯一能「制造召回」的方向——防止把伪装成企业站的骗局冷存。
        if p_target >= TARGET_VETO and rule.confidence < 0.75:
            return PurposeResult(
                purpose="unknown", confidence=0.0, source="fused",
                reasons=[f"规则判「{rule.label}」（{rule.confidence:.2f}）"
                         f"但模型认为有 {p_target:.0%} 概率是落地页，不做排除"],
                scores=rule.scores, model_probs=probs,
            )
        # 规则弱、模型强烈认为经营型：加一点置信，让弱判也能落闸。
        if rule.confidence < 0.65 and p_target <= OPERATIONAL_CONFIRM:
            rule.confidence = min(0.85, rule.confidence + MODEL_AGREE_BOOST)
            rule.reasons.append(f"模型确认经营型（p_target={p_target:.2f}）")
        rule.source = "fused"
        return rule

    if rule.purpose == "unknown" and p_target <= OPERATIONAL_STRONG:
        # 规则没认出来，模型非常确定不是落地页形态。给一个通用档，
        # 由 decide_suppression 再叠加「骗局词/硬证据」保护。
        return PurposeResult(
            purpose="operational", confidence=0.60, source="model",
            reasons=[f"规则未识别，模型判定为经营型站点（p_target={p_target:.2f}）"],
            scores=rule.scores, model_probs=probs,
        )

    # 规则已判落地页/分发页/未知：不做任何干预，照常走风险判定。
    return rule


def classify(
    feats: FeatureBundle,
    *,
    host: str = "",
    facts: dict[str, Any] | None = None,
    use_model: bool = True,
) -> PurposeResult:
    """规则 + 模型融合。这是唯一对外入口。"""
    facts = facts or {}
    is_gov = bool(facts.get("is_government"))
    is_media = bool(facts.get("is_media"))
    if not is_gov or not is_media:
        try:
            from .whitelist import get_whitelist

            wl = get_whitelist()
            is_gov = is_gov or wl.is_government(host)
            is_media = is_media or wl.is_media(host)
        except Exception:  # noqa: BLE001 白名单缺失不影响分类
            pass

    rule = classify_rules(feats, host=host, is_government=is_gov, is_media=is_media)
    if not use_model:
        return rule

    payload = load_model()
    if not payload or payload.get("task") != "binary_shape":
        return rule

    _, _, _, probs = _predict_model(payload, feats)
    return fuse(rule, float(probs.get("target_shaped", 0.0)), probs,
                is_government=is_gov, is_media=is_media)


# ---------------------------------------------------------------------------
# 抑制判定：给 triage 用
# ---------------------------------------------------------------------------

# 这些事实一旦成立，用途判定失效——骗子会把自己伪装成「企业官网」。
_HARD_FACTS = ("fake_site_id", "fake_icp", "impersonation")


def _gate_veto(text: str) -> str:
    """页面里有没有「经营型」的反证词。返回命中的词，便于写理由。"""
    m = GATE_VETO.search(text or "")
    return m.group(0) if m else ""


def decide_suppression(
    result: PurposeResult,
    facts: dict[str, Any],
    feats: FeatureBundle | None = None,
    *,
    text: str = "",
) -> tuple[bool, str]:
    """返回 (是否抑制高风险队列, 理由)。调用方据此降级，不删除资产。

    「不疏漏」在这里落实：只要有任意一条硬证据或者骗局形态，用途判定就让位。
    宁可让一个客服站留在候选池，也不能让一个伪装成企业站的骗局冷存。
    """
    claim = facts.get("claim") or {}
    verdict = str(claim.get("verdict") or "") if isinstance(claim, dict) else ""
    if verdict in _HARD_FACTS:
        return False, f"存在冒充硬证据（{verdict}），忽略用途判定"
    if facts.get("official_listed") or facts.get("linked_confirmed_campaign"):
        return False, "存在官方/团伙级硬证据，忽略用途判定"
    if facts.get("forces_apk_download") or facts.get("apk_links"):
        return False, "分发安装包，用途不参与排除"
    v = (feats.values if feats else {})
    if v.get("id_inputs", 0) >= 1 or v.get("tel_inputs", 0) >= 2:
        return False, "表单索要证件/手机号，用途不参与排除"

    # 骗局特征成串出现时不抑制：哪怕页面同时有「关于我们」和「解决方案」
    if int(result.scam_hits or 0) >= 2:
        return False, "骗局专属词命中 ≥2，忽略用途判定"

    veto = _gate_veto(text)
    if veto:
        return False, f"页面含「{veto}」，不适用用途排除"

    # 模型独判的「经营型」没有规则依据，只在页面确实是个成规模的站点时
    # 才给排除权（正文够长、不像单页落地）。二分类只回答「像不像落地页」：
    # 赌场、盗播站内容都很长，一样落到这一档——所以上面那道否决先跑。
    if result.purpose == "operational" and result.source == "model":
        if len(text or "") < 600:
            return False, "仅模型判定经营型且正文过短，不足以排除"

    if result.purpose in NON_TARGET and result.confidence >= MIN_CONFIDENCE:
        return True, f"用途为「{result.label}」，不占高危队列（保留记录，可随时复查）"
    if result.purpose in SOFT_NON_TARGET and result.confidence >= 0.70:
        return True, f"用途为「{result.label}」，降为候选并保留（行业门户常被仿冒）"
    return False, ""


def analyze(
    feats: FeatureBundle,
    *,
    host: str = "",
    facts: dict[str, Any] | None = None,
    use_model: bool = True,
    text: str = "",
) -> PurposeResult:
    """分类 + 抑制判定，一步到位。"""
    facts = facts or {}
    enabled = True
    suppress_enabled = True
    try:
        from .config import settings

        enabled = bool(settings.purpose_enabled)
        suppress_enabled = bool(settings.purpose_suppress)
    except Exception:  # noqa: BLE001 配置异常时保持默认开启
        pass
    if not enabled:
        return PurposeResult(purpose="unknown", confidence=0.0, source="none",
                             reasons=["用途分类已关闭"])

    result = classify(feats, host=host, facts=facts, use_model=use_model)
    try:
        result.scam_hits = int(feats.values.get("kw_scam", 0) or 0)
    except (TypeError, ValueError):
        result.scam_hits = 0
    # host 一并送进去：站群命名（xx-douyin.cc）只有连域名一起看才拦得住
    probe = f"{host} {text}" if host else text
    suppressed, reason = decide_suppression(result, facts, feats, text=probe)
    if suppressed and not suppress_enabled:
        result.suppressed = False
        result.suppressed_reason = reason + "（闸门已关闭，仅记录）"
        return result
    result.suppressed = suppressed
    result.suppressed_reason = reason
    return result
