"""填表载荷：把「往哪个框填什么」变成一份扩展能照做的动作清单。

扩端只实现动作原语，不认识任何具体网站；渠道改版时改这里即可。

动作原语
--------
``cookie``    预置 cookie（12377 靠 bigHarmType 决定表单里有哪些小类）
``select``    下拉选择，value 或 text 匹配
``radio``     单选，按 value 或可见文字匹配
``check``     勾选框
``fill``      文本输入／文本域（原生 setter + 事件，兼容 React/Vue 受控组件）
``attach``    取回附件并塞进 file input（DataTransfer）
``highlight`` 只高亮提示，不代填（验证码、提交按钮）
``wait``      等待元素出现
"""

from __future__ import annotations

from typing import Any

from .channels import Channel
from .narrative import Ctx


def _s(action: str, **kw: Any) -> dict[str, Any]:
    return {"action": action, **kw}


def _urls(ctx: Ctx) -> list[str]:
    out = [ctx.asset.value] if getattr(ctx.asset, "kind", "") in {"url", "domain"} else []
    for u in ctx.extra_urls:
        if u and u not in out:
            out.append(u)
    return out[:20]


def build(
    channel: Channel,
    ctx: Ctx,
    body: str,
    api_base: str,
    bundle_id: str,
    names: dict[str, str] | None = None,
) -> dict[str, Any]:
    cid = channel.id
    urls = _urls(ctx)
    primary = urls[0] if urls else (getattr(ctx.asset, "value", "") or "")

    pre: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    manual: list[str] = []

    if cid == "12377" and ctx.harm:
        pre.append(_s("cookie", name="bigHarmType", value=ctx.harm.big, path="/", secure=True))
        pre.append(_s("cookie", name="BIG_HARM", value=ctx.harm.label.split(" / ")[0], path="/", secure=True))
        steps += [
            _s("wait", selector="#harm_category", timeout=8000),
            _s("select", selector="#report_platform", value=ctx.harm.platform,
               note="被举报平台：" + {"WEBSITE": "网站网页", "APP": "APP", "ACCOUNT": "网络账号"}[ctx.harm.platform]),
            _s("select", selector="#harm_category", value=ctx.harm.small, note="危害小类：" + ctx.harm.small_name),
        ]
        if ctx.harm.platform == "WEBSITE":
            host = (ctx.asset.normalized or ctx.asset.value)
            steps += [
                _s("fill", selector="#website_name", value=(ctx.facts.get("page_title") or host)[:40]),
                _s("fill", selector="#website_address", value="\n".join(urls), multiline=True),
            ]
        elif ctx.harm.platform == "APP":
            steps += [
                _s("fill", selector="#app_name", value=(ctx.asset.value or "")[:40]),
                _s("select", selector="#app_source", text="APP下载地址"),
                _s("fill", selector="#app_address_area", value="\n".join(urls), multiline=True),
            ]
        else:
            steps += [
                _s("select", selector="#platform_category", text="其他"),
                _s("fill", selector="#qt_account", value=(ctx.asset.value or "")[:40]),
                _s("fill", selector="#qt_yh_address", value="\n".join(urls), multiline=True),
            ]
        steps += [
            _s("fill", selector="#report_content", value=body, multiline=True),
            _s("attach", selector="#upload_file", file="zip", note="证据包"),
            _s("highlight", selector="#verify_code", note="请填写图形验证码"),
            _s("highlight", selector=".btn.primary", note="核对无误后点「提交」"),
        ]
        manual += ["登录 12377 账号", "填写图形验证码", "点提交"]

    elif cid == "12321" and ctx.harm:
        steps += [
            _s("wait", selector="#web_url", timeout=8000),
            _s("radio", selector='input[name="tslx"]', value="0", note="投诉类型：不良网站"),
            _s("fill", selector="#web_url", value=primary),
            _s("radio", selector='input[name="type"]', value=ctx.harm.type_12321,
               note="不良类型：" + {"0": "淫秽色情", "1": "钓鱼及诈骗", "2": "泄漏隐私",
                                "3": "反动及政治敏感", "4": "其他违法"}[ctx.harm.type_12321]),
            _s("fill", selector="#sms_content", value=body, multiline=True),
            _s("check", selector="#xuzhi", note="已阅并同意投诉须知"),
            _s("highlight", selector="#sub_jb", note="点「提交投诉」后需手动拖动滑块"),
        ]
        manual += ["拖动滑块完成验证", "点提交投诉"]
        if len(body) > 2000:
            manual.append("正文已接近 2200 字上限，注意页面提示")

    elif cid == "qq_urlsec":
        steps += [
            _s("wait", selector="#url", timeout=8000),
            _s("fill", selector="#url", value=primary),
            _s("fill", selector="#reason", value=body, multiline=True),
            _s("fill", selector="#email", value="", note="如需要回执，请填邮箱"),
            _s("attach", selector='input[type="file"]', file="pdf", note="网站截图／材料"),
            _s("highlight", selector="#do", note="点提交（会弹腾讯防水墙验证）"),
        ]
        manual += ["（可选）填写邮箱以接收结果", "点提交"]

    elif cid in {"cf_abuse", "registrar_abuse"}:
        # 走通用标签匹配：这些站字段少、label 稳定
        fields = [
            ("网址", primary),
            ("URL", primary),
            ("描述", body),
            ("Description", body),
            ("邮箱", ""),
            ("Email", ""),
        ]
        steps.append(_s("auto_label", fields=fields, note="按标签文字匹配填充"))
        manual += ["页面校验（Turnstile／图形码）", "点提交"]

    return {
        "bundle_id": bundle_id,
        "channel": channel.id,
        "entry_url": channel.entry_url,
        "pre": pre,
        "steps": steps,
        "manual": manual,
        "files": {
            "zip": f"{api_base}/api/report/bundles/{bundle_id}/file?kind=zip",
            "pdf": f"{api_base}/api/report/bundles/{bundle_id}/file?kind=pdf",
        },
        # 附件文件名要原样带过去：12377 按后缀白名单校验，缺了 .zip 会被直接拒绝
        "file_names": names or {},
        "constraints": {
            "body_limit": channel.body_limit,
            "max_urls": channel.max_urls,
            "attachment": channel.attachment,
        },
    }
