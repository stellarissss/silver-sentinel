"""涉老判定：这个站是不是在骗老人的钱。

为什么单独算
------------
现有的分数回答的是「像不像黑产站群」。涉老诈骗不是那套画像的子集：
它域名随机、页面朴素、没有站群，靠一条短信传播，三五天就换。

所以这里换一个问法——**四个要素凑齐了几个**：

    audience  受众指向：养老、退休、社保、医保、补贴，或民族资产解冻这类
              专门盯着老人的骗局类型
    identity  身份索取：身份证、银行卡、社保卡、人脸、验证码
    authority 权威冒用：伪造标识码、冒充部委、编造红头文件
    action    转化动作：下载 APK、加微信、扫码、限时领取

「受众指向」是必要条件——没有它，博彩站和盗播站也会被算进来。
其余三项是证据，凑够两条才算涉老，凑够三条且含身份或权威才是 P0。

实测（把真实样本喂进系统）
------------------------
    np4w53.cn  2026年个人财政补贴申领   受众(补贴) 身份(身份证) 权威(bm01000001) 动作(倒计时) = 4 → P0
    nuanyang  中国老龄康养服务平台      受众(老龄) 权威(冒充民政部) 动作(APK)          = 3 → P0
    s.qka91   中稀同心·惠民资金审核表   受众(惠民资金) 权威(冒充国办)                  = 2 → 涉老
    xindazx   沈阳补贴指南              受众(补贴)                                     = 1 → 不涉老
    mz88      泰文赌场                  受众(无)                                       = 0 → 不涉老

判错的代价不对称：把正规养老院判成涉老，只是多一条人工复核；
把「养老金补发」页面判成不涉老，是有人当天被骗走一辈子的钱。
所以阈值往宽了取，宁可多报。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 词表

# 受众指向：老人的钱袋子。前两行是身份，中间两行是钱，最后一行是骗局类型。
_AUDIENCE = re.compile(
    r"养老|老龄|老年|老人|退休|银发|长辈|爸妈|父母|晚年|"
    r"社保|医保|养老金|退休金|公积金|高龄|"
    r"补贴|补助|津贴|救济|扶贫|低保|惠民|"
    r"民族资产解冻|资产解冻|国家项目|国家保密工程|云数贸|五行币|善心汇|"
    r"以房养老|消费养老|康养|保健|养生|健康讲座|义诊|特效药"
)

# 身份索取：填了就能盗刷，或者拿去卖。
# 只认「要求你交出来」的语境——正规办事指南也会出现「身份证」三个字，
# 那是告诉你带什么材料，不是让你输进去。线上误报：tuiyijunren.cn
# （退役军人资讯站，正文写了办证要带身份证）被判「涉老 P1」。
_IDENTITY = re.compile(
    r"(?:填写|输入|上传|提交|绑定)[^。；\n]{0,10}"
    r"(?:身份证|证件号|银行卡|卡号|社保卡|医保卡|验证码|支付密码|交易密码)"
    r"|身份证正反面|人脸识别|刷脸认证|活体检测"
)

# 权威冒用：判据优先用 claim 的结论（它能识别伪造标识码），
# 这里只兜底「页面上写了但 claim 没抓到的」。
_AUTHORITY = re.compile(
    r"国务院|财政部|民政部|人力资源社会保障部|人社部|卫健委|国家医保局|"
    r"国家市场监督管理总局|税务总局|公安部|中央人民政府|"
    r"红头文件|国徽|政府网站标识码|文件号|中办|国办"
)

# 转化动作：把人往站外带，或者逼人马上做决定。
_ACTION = re.compile(
    r"加微信|添加微信|扫码|扫描二维码|微信客服|企业微信|"
    r"下载安装|立即下载|安卓版|安装包|"
    r"免费领取|免费领|"
    r"立即领取|马上领取|限时|仅剩|名额有?限|倒计时|今日截止|过期作废"
)

AUTHORITY_CLAIMS = frozenset({"fake_site_id", "fake_icp", "impersonation", "fabricated_agency"})


def _hits(pattern: re.Pattern[str], text: str, limit: int = 6) -> list[str]:
    out: list[str] = []
    for m in pattern.finditer(text or ""):
        w = m.group(0)
        if w not in out:
            out.append(w)
        if len(out) >= limit:
            break
    return out


def _num(v: Any) -> int:
    if isinstance(v, (list, tuple, set, dict)):
        return len(v)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class ElderSignal:
    is_elder: bool = False
    priority: str = "P2"
    score: int = 0
    hits: dict[str, list[str]] = field(default_factory=dict)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "elder": self.is_elder,
            "priority": self.priority,
            "score": self.score,
            "hits": {k: v for k, v in self.hits.items() if v},
            "reason": self.reason,
        }


def assess(facts: dict[str, Any], text: str = "") -> ElderSignal:
    """从已采集的事实判「是不是在骗老人」。

    只读 facts 与正文，不发网络请求——它要在取证流水线里每站跑一次，
    也要能在 `rescore` 里对历史资产补算。
    """
    body = (text or "")[:40000]
    feats = facts.get("features") or {}
    claim = facts.get("claim") or {}
    verdict = (claim.get("verdict") or "neutral") if isinstance(claim, dict) else "neutral"

    audience = _hits(_AUDIENCE, body)
    identity = _hits(_IDENTITY, body)

    # 表单里有身份证/银行卡输入框，比正文里的词更硬：那是要人真填。
    id_inputs = _num(facts.get("id_inputs") or (feats.get("id_inputs") if isinstance(feats, dict) else 0))
    if id_inputs and not identity:
        identity = [f"表单含 {id_inputs} 个证件/卡号输入框"]

    # 权威冒用只认结构化判定（claim 抽的是 header/版权行里的自称，
    # 有语境），不认正文词频——正规站天天引用「民政部」「国务院」。
    # 线上误报：tuiyijunren.cn 正文提到部委政策，被判「涉老 P1」。
    authority: list[str] = []
    if verdict in AUTHORITY_CLAIMS:
        authority.append(f"自称被判为{verdict}")
        agencies = claim.get("agencies") if isinstance(claim, dict) else None
        if agencies:
            authority.extend(list(agencies)[:3])
    elif verdict in ("neutral", "") and _hits(_AUTHORITY, body) and re.search(
        r"(?:审核|主导建设|授权|批准|主办|直属|下属)", body
    ):
        # 兜底：正文写了部委 AND 写得像「这个项目归它管」。
        # 两个条件缺一不可，否则引用政策文件的页面全中。
        authority = _hits(_AUTHORITY, body)[:3]

    action = _hits(_ACTION, body)
    apk = _num(facts.get("apk_links") or (feats.get("apk_links") if isinstance(feats, dict) else 0))
    if apk:
        action = [f"页面分发 {apk} 个安装包"] + action

    score = sum(1 for x in (audience, identity, authority, action) if x)
    sig = ElderSignal(
        score=score,
        hits={"audience": audience, "identity": identity,
              "authority": authority, "action": action},
    )

    if not audience:
        sig.reason = "无受众指向"
        return sig

    if score < 2:
        sig.reason = "只有受众指向，缺证据"
        return sig

    # 「受众 + 营销动作」不等于涉老诈骗——那是所有营销页的写法
    # （「免费领取方案」「限时优惠」「下载 App」）。
    # 涉老必须有**冒充权威**或**索取身份**，这两样正常机构不会做。
    # 线上误报：tuiyijunren.cn（正规退役军人资讯站）、
    # meituanshangjiabandenglurukou.shop（仿冒美团）都栽在这条。
    hard = bool(identity or authority)
    if not hard:
        sig.reason = "只有受众指向和营销动作，缺冒充或身份索取"
        return sig

    sig.is_elder = True
    if score >= 3 and hard:
        sig.priority = "P0"
        sig.reason = "受众指向 + " + "、".join(
            k for k, v in (("身份索取", identity), ("权威冒用", authority),
                           ("转化动作", action)) if v
        )
    else:
        sig.priority = "P1"
        sig.reason = "涉老但证据不足两条硬指标"
    return sig
