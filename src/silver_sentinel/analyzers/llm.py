"""LLM 研判层。

定位：**补充而非替代**规则引擎。
- 规则给的是可核对的结构化证据，LLM 负责把证据串成「这套剧本讲到第几步」；
- 没有 key、超时、输出不合规时一律返回 None（弃权），绝不编一个看起来合理的结论；
- 送进模型的文本先脱敏，手机号/身份证/银行卡不出本地。
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..config import settings

SYSTEM_PROMPT = """你是反诈骗研判分析师，专门分析针对中国老年人的诈骗线索（俗称「领鸡蛋骗局」）。
这类骗局通常的链条是：免费礼品引流 → 健康讲座/社群洗脑 → 小额返利建立信任 → 推销高价无效产品，或以「国家项目」「民族资产解冻」「养老补贴」为名诱导下载仿冒 App 并投资。

你会收到一份结构化证据包，包含：资产信息、已命中的规则信号、文本摘录、技术特征。

严格遵循：
1. 只依据给出的证据推理，不得引入证据之外的假设。不要编造公司名、案号、金额。
2. 如果证据不足以支撑判断，classification 必须是 "unclear"，并在 missing_evidence 里列出还差什么。
3. 你的结论不构成法律定性，用词保持克制（"高度符合""疑似"而非"确定是"）。
4. 只输出一个 JSON 对象，不要 Markdown 代码块，不要解释性前后缀。

输出字段：
{
  "classification": "elderly_scam" | "likely_scam" | "unclear" | "likely_benign",
  "confidence": 0.0-1.0,
  "stage": "引流" | "洗脑" | "小额返利" | "收割" | "未知",
  "tactics": ["具体手法，每条不超过 20 字"],
  "target_group": "被瞄准的人群特征",
  "reasoning": "不超过 200 字的推理，必须引用证据中的具体信号 id 或文本片段",
  "missing_evidence": ["还需要什么证据才能定论"],
  "recommended_action": "给家属或社区工作者的一条具体建议"
}"""

_PHONE = re.compile(r"(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)")
_IDCARD = re.compile(r"(?<!\d)(\d{6})\d{8}(\d{3}[\dXx])(?!\d)")
_BANKCARD = re.compile(r"(?<!\d)(\d{4})\d{8,11}(\d{4})(?!\d)")


def redact(text: str) -> str:
    """送模型前脱敏。保留前几位用于人工比对，中间打码。"""
    text = _IDCARD.sub(r"\1********\2", text)
    text = _BANKCARD.sub(r"\1 **** **** \2", text)
    text = _PHONE.sub(r"\1****\2", text)
    return text


def _extract_json(raw: str) -> dict | None:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    start, end = raw.find("{"), raw.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _validate(data: dict | None) -> dict | None:
    if not isinstance(data, dict):
        return None
    classification = str(data.get("classification", "")).lower()
    if classification not in {"elderly_scam", "likely_scam", "unclear", "likely_benign"}:
        return None
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0))))
    except (TypeError, ValueError):
        confidence = 0.0

    def as_list(value: Any, cap: int = 8) -> list[str]:
        if isinstance(value, str):
            return [value[:120]]
        if isinstance(value, list):
            return [str(v)[:120] for v in value[:cap]]
        return []

    return {
        "classification": classification,
        "confidence": round(confidence, 3),
        "stage": str(data.get("stage", "未知"))[:16],
        "tactics": as_list(data.get("tactics")),
        "target_group": str(data.get("target_group", ""))[:80],
        "reasoning": str(data.get("reasoning", ""))[:600],
        "missing_evidence": as_list(data.get("missing_evidence")),
        "recommended_action": str(data.get("recommended_action", ""))[:200],
        "model": settings.llm_model,
    }


def analyze(payload: dict[str, Any]) -> dict[str, Any] | None:
    """调用 LLM。任何环节不满足预期都返回 None。"""
    if not settings.llm_ready:
        return None

    user_content = json.dumps(payload, ensure_ascii=False, indent=2)
    user_content = redact(user_content)
    if len(user_content) > 24000:
        user_content = user_content[:24000] + "\n…（证据已截断）"

    body = {
        "model": settings.llm_model,
        "temperature": 0.1,
        "max_tokens": 900,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }

    try:
        with httpx.Client(timeout=settings.llm_timeout) as client:
            resp = client.post(
                f"{settings.llm_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.llm_api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
        if resp.status_code != 200:
            return None
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError):
        return None

    return _validate(_extract_json(content))


def status() -> dict[str, Any]:
    return {
        "configured": settings.llm_ready,
        "model": settings.llm_model if settings.llm_ready else "",
        "behavior": "启用" if settings.llm_ready else "未配置，研判仅依赖规则引擎（LLM 环节自动弃权）",
    }
