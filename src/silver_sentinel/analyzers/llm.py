"""LLM 研判层。

定位：**补充而非替代**规则引擎。
- 规则给的是可核对的结构化证据，LLM 负责把证据串成「这套剧本讲到第几步」；
- 没有 key、超时、输出不合规时一律返回 None（弃权），绝不编一个看起来合理的结论；
- 送进模型的文本先脱敏，手机号/身份证/银行卡不出本地。
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from .. import runtime_settings
from ..config import settings

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是反诈骗研判分析师，专门分析针对中国老年人的诈骗线索（俗称「领鸡蛋骗局」）。
这类骗局通常的链条是：免费礼品引流 → 健康讲座/社群洗脑 → 小额返利建立信任 → 推销高价无效产品，或以「国家项目」「民族资产解冻」「养老补贴」为名诱导下载仿冒 App 并投资。

你会收到一份结构化证据包，包含：资产信息、已命中的规则信号、页面正文摘录、技术特征、证据编号。

严格遵循：
1. 只依据给出的证据推理，不得引入证据之外的假设。不要编造公司名、案号、金额。
2. 如果证据不足以支撑判断，classification 必须是 "unclear"，并在 missing_evidence 里列出还差什么。
3. 你的结论不构成法律定性，用词保持克制（"高度符合""疑似"而非"确定是"）。
4. reasoning 里必须用 [E:编号] 标注你引用的证据，例如「页面承诺每日返利 [E:1234]」。没有把握的不要引。
5. 只输出一个 JSON 对象，不要 Markdown 代码块，不要解释性前后缀。

输出字段：
{
  "classification": "elderly_scam" | "likely_scam" | "unclear" | "likely_benign",
  "confidence": 0.0-1.0,
  "stage": "引流" | "洗脑" | "小额返利" | "收割" | "未知",
  "tactics": ["具体手法，每条不超过 20 字"],
  "target_group": "被瞄准的人群特征",
  "reasoning": "不超过 200 字的推理，必须引用证据编号",
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

    reasoning = str(data.get("reasoning", ""))[:600]
    # 引用编号：模型声称引用了哪条证据。只收录格式合法的，避免把幻觉当依据。
    cited = sorted({m for m in re.findall(r"\[E:(\d{1,9})\]", reasoning)})

    return {
        "classification": classification,
        "confidence": round(confidence, 3),
        "stage": str(data.get("stage", "未知"))[:16],
        "tactics": as_list(data.get("tactics")),
        "target_group": str(data.get("target_group", ""))[:80],
        "reasoning": reasoning,
        "missing_evidence": as_list(data.get("missing_evidence")),
        "recommended_action": str(data.get("recommended_action", ""))[:200],
        "cited_evidence": cited,
        "model": runtime_settings.llm_config().get("model") or settings.llm_model,
    }


def analyze(payload: dict[str, Any]) -> dict[str, Any] | None:
    """调用 LLM。任何环节不满足预期都返回 None。"""
    cfg = runtime_settings.llm_config()
    if not cfg["ready"]:
        return None

    user_content = json.dumps(payload, ensure_ascii=False, indent=2)
    user_content = redact(user_content)
    if len(user_content) > 24000:
        user_content = user_content[:24000] + "\n…（证据已截断）"

    body = {
        "model": cfg["model"],
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
                f"{cfg['base_url']}/chat/completions",
                headers={
                    "Authorization": f"Bearer {cfg['api_key']}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
        if resp.status_code != 200:
            # 以前这里静默返回 None，界面上只看到「LLM 未参与」，查不出原因。
            # 401/404/402 各对应密钥、模型名、余额，必须说出来。
            log.warning("LLM 调用失败 HTTP %s：%s", resp.status_code, resp.text[:300])
            return None
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage") or {}
    except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError) as exc:
        log.warning("LLM 调用异常：%s: %s", type(exc).__name__, exc)
        return None

    result = _validate(_extract_json(content))
    if result is None:
        log.warning("LLM 输出不符合约定结构：%s", str(content)[:200])
        return None
    result["usage"] = {
        "prompt": usage.get("prompt_tokens", 0),
        "completion": usage.get("completion_tokens", 0),
        "total": usage.get("total_tokens", 0),
    }
    return result


def test_connection(*, base_url: str = "", api_key: str = "", model: str = "") -> dict[str, Any]:
    """给设置页用的连通性测试。不写入任何状态，只回显耗时与模型回答。"""
    cfg = runtime_settings.llm_config()
    base = (base_url or cfg["base_url"]).rstrip("/")
    key = api_key or cfg["api_key"]
    name = model or cfg["model"]
    if not base or not key:
        return {"ok": False, "error": "缺少 Base URL 或 API Key"}

    started = time.monotonic()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": name,
                    "max_tokens": 24,
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": "只回复两个字：连通"},
                        {"role": "user", "content": "测试"},
                    ],
                },
            )
        elapsed = round(time.monotonic() - started, 2)
        if resp.status_code != 200:
            detail = resp.text[:300]
            return {"ok": False, "status": resp.status_code, "error": detail, "elapsed": elapsed}
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage") or {}
        return {"ok": True, "model": name, "reply": str(content)[:80], "elapsed": elapsed, "usage": usage}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}


def status() -> dict[str, Any]:
    cfg = runtime_settings.llm_config()
    return {
        "configured": cfg["ready"],
        "model": cfg["model"] if cfg["ready"] else "",
        "behavior": "启用" if cfg["ready"] else "未配置，研判仅依赖规则引擎（LLM 环节自动弃权）",
        "gray_band": [cfg["gray_low"], cfg["gray_high"]],
    }
