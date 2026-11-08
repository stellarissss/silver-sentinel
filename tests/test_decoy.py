"""诱饵与蜜罐：这一页是不是样子货。

测试的核心不是「能不能识别诱饵」，而是**两头都不能错**：

    把 WAF 挑战页当诱饵  → 一批正常站被记成「故意伪装」，污染证据链
    把诱饵当正常页        → 判定引擎看到空壳，直接漏判（暖阳那次就是这个坑）

所以每条正向用例都配一条反向用例：真公告里写「安全检测」不算诱饵，
正常表单里的 csrf token 不算陷阱字段。
"""

from __future__ import annotations

from silver_sentinel import decoy

CF_CHALLENGE = """
<!DOCTYPE html><html><head><title>Just a moment...</title></head>
<body><div id="cf-browser-verification">Checking your browser before accessing.
Enable JavaScript and cookies to continue.</div>
<script>window._cf_chl_opt={cvId:'3'}</script></body></html>
"""

SEC_CHECK_DECOY = """
<html><head><title>安全检测中心</title></head>
<body>
<div class="box">正在检测您的设备环境，请稍候…</div>
<a href="/go/app.apk">继续</a>
</body></html>
"""

SEC_CHECK_NO_EXIT = """
<html><head><title>请稍候</title></head>
<body><div>正在跳转，请稍候</div></body></html>
"""

LONG_NOTICE = (
    "<html><body><h1>关于开展2026年度养老保险待遇资格认证的通知</h1>"
    + "<p>各参保单位：为做好待遇资格认证工作，系统将进行安全检测与身份核验。"
    "认证时间为2026年1月1日至3月31日，请携带身份证到就近服务网点办理。</p>" * 8
    + "</body></html>"
)

REDIRECT_SHELL = """<html><head><meta http-equiv="refresh" content="0;url=https://next.example.com/x"></head>
<body></body></html>"""

EXPIRED_PAGE = """
<html><head><title>提示</title></head>
<body><div>本次活动已结束，感谢参与。</div></body></html>
"""

HONEYPOT_FORM = """
<html><body><form method="post" action="/submit">
<input type="text" name="name" placeholder="姓名">
<input type="text" name="idcard" placeholder="身份证号">
<input type="text" name="email_confirm" style="display:none">
<button>提交</button></form></body></html>
"""

ANTI_AUTOMATION = """
<html><head><title>系统提示</title></head><body>
<div>检测到自动化访问环境，请关闭开发者工具后重试</div>
<script>
if (navigator.webdriver) { document.body.innerHTML = '检测到自动化'; }
setInterval(function(){ debugger; }, 1000);
</script>
</body></html>
"""

NORMAL_PAGE = """
<html><head><title>某某市人力资源和社会保障局</title></head><body>
<h1>办事指南</h1><p>办理退休手续请携带身份证、户口本到窗口办理。</p>
<p>咨询电话 12333。办公时间：周一至周五 9:00-17:00。</p>
</body></html>
"""


def test_cf_challenge_is_interstitial_not_decoy():
    """WAF 挑战页必须被摘出去。

    它的标题就是「安全检测」，正文也极短——不先识别出来，
    每一批被墙的站都会变成「诱饵」，而拿 WAF 页判低分会把正常站永久沉底。
    """
    sig = decoy.assess(html=CF_CHALLENGE, text="Checking your browser", title="Just a moment...",
                       status=503, final_url="https://a.example.com/",
                       request_host="a.example.com", html_len=len(CF_CHALLENGE))
    assert sig.is_interstitial()
    assert "Cloudflare" in sig.blocked_by
    assert not sig.is_decoy


def test_security_check_decoy_with_download():
    sig = decoy.assess(html=SEC_CHECK_DECOY, text="正在检测您的设备环境，请稍候…继续",
                       title="安全检测中心", status=200,
                       final_url="https://x.example.cn/", request_host="x.example.cn",
                       html_len=len(SEC_CHECK_DECOY), apk_links=["https://x.example.cn/go/app.apk"])
    assert sig.is_decoy
    assert sig.kind == "security_check"
    assert sig.weight == 3
    assert sig.downstream


def test_security_check_without_exit_is_not_decoy():
    """只写「请稍候」没有去向：可能真是坏页面。给弱信号，不判诱饵。"""
    sig = decoy.assess(html=SEC_CHECK_NO_EXIT, text="正在跳转，请稍候", title="请稍候",
                       status=200, final_url="https://x.example.cn/", request_host="x.example.cn",
                       html_len=len(SEC_CHECK_NO_EXIT))
    assert not sig.is_decoy
    assert sig.weight == 0


def test_long_notice_mentioning_security_check_is_not_decoy():
    """真公告里写「系统将进行安全检测」是正常句子。长度是这里最重要的判据。"""
    sig = decoy.assess(html=LONG_NOTICE, text="关于开展2026年度养老保险待遇资格认证的通知" * 20,
                       title="关于开展2026年度养老保险待遇资格认证的通知",
                       status=200, final_url="https://gov.example.cn/", request_host="gov.example.cn",
                       html_len=len(LONG_NOTICE) * 8)
    assert not sig.is_decoy


def test_redirect_shell():
    sig = decoy.assess(html=REDIRECT_SHELL, text="", title="", status=200,
                       final_url="https://old.example.cn/", request_host="old.example.cn",
                       html_len=len(REDIRECT_SHELL))
    assert sig.is_decoy
    assert sig.kind == "redirect_shell"
    assert any("next.example.com" in u for u in sig.downstream)


def test_expired_page_counts_as_evidence_of_past_operation():
    """「活动已结束」本身是证据：没有申领，哪来的结束。"""
    sig = decoy.assess(html=EXPIRED_PAGE, text="本次活动已结束，感谢参与。", title="提示",
                       status=200, final_url="https://y.example.cn/", request_host="y.example.cn",
                       html_len=len(EXPIRED_PAGE))
    assert sig.is_decoy
    assert sig.kind == "expired"
    assert sig.weight == 2


def test_hidden_trap_field_is_honeypot():
    sig = decoy.assess(html=HONEYPOT_FORM, text="姓名 身份证号 提交", title="信息登记",
                       status=200, final_url="https://z.example.cn/", request_host="z.example.cn",
                       html_len=len(HONEYPOT_FORM))
    assert sig.honeypot
    assert any("email_confirm" in r for r in sig.honeypot_reasons)


def test_csrf_hidden_field_is_not_trap():
    """正常表单用 hidden 存 csrf token。只看「隐藏」会把所有正常表单判成蜜罐。"""
    html = ('<form><input type="hidden" name="csrf_token" value="abc">'
            '<input type="text" name="name"></form>')
    sig = decoy.assess(html=html, text="姓名 提交", title="报名", status=200,
                       final_url="https://ok.example.cn/", request_host="ok.example.cn",
                       html_len=len(html))
    assert not sig.honeypot


def test_anti_automation_detection():
    sig = decoy.assess(html=ANTI_AUTOMATION, text="检测到自动化访问环境，请关闭开发者工具后重试",
                       title="系统提示", status=200,
                       final_url="https://h.example.cn/", request_host="h.example.cn",
                       html_len=len(ANTI_AUTOMATION))
    assert sig.honeypot
    assert any("反调试死循环" in r for r in sig.honeypot_reasons)


def test_normal_page_has_no_signal():
    sig = decoy.assess(html=NORMAL_PAGE, text="办事指南 办理退休手续请携带身份证、户口本到窗口办理。咨询电话 12333。",
                       title="某某市人力资源和社会保障局", status=200,
                       final_url="https://rsj.example.gov.cn/", request_host="rsj.example.gov.cn",
                       html_len=len(NORMAL_PAGE))
    assert not sig.is_decoy
    assert not sig.honeypot
    assert not sig.blocked_by


def test_honeypot_report_from_guard_is_carried_over():
    sig = decoy.assess(html="<html><body>hello</body></html>", text="hello", title="",
                       status=200, final_url="https://m.example.cn/", request_host="m.example.cn",
                       honeypot_report={"suspected": True, "reasons": ["页面回显了采集端 IP"]})
    assert sig.honeypot
    assert any("采集端 IP" in r for r in sig.honeypot_reasons)


def test_action_evidence_from_dict():
    """取证时 facts["decoy"] 是 dict，elder 直接读它。"""
    note = decoy.action_evidence({
        "is_decoy": True, "kind": "security_check",
        "downstream": ["https://d7k2m.cn/submit.php"],
    })
    assert "安全核验" in note
    assert "d7k2m.cn" in note


def test_triage_note_never_promotes_interstitial():
    tier, why = decoy.triage_note({"blocked_by": "Cloudflare 挑战", "is_decoy": False}, elder=False)
    assert tier == ""
    assert "拦截" in why


def test_triage_note_keeps_decoy_with_exit_in_candidate():
    tier, why = decoy.triage_note(
        {"is_decoy": True, "weight": 3, "downstream": ["https://a.cn/2"], "reason": "核验诱饵页"},
        elder=False,
    )
    assert tier == "candidate"
    assert "分发节点" in why


# ---------------------------------------------------------------- 与判定链的衔接


def test_decoy_supplies_action_evidence_to_elder():
    """诱饵本身不含涉老词，但它提供了「转化动作」这第四条证据。

    这正是暖阳那次漏判补上的那一段：首页只有「安全检测中心」，
    但下一跳在收身份证——把人送过去就是动作。
    """
    from silver_sentinel.elder import assess as assess_elder

    sig = assess_elder(
        {
            "decoy": {
                "is_decoy": True,
                "kind": "security_check",
                "downstream": ["https://d7k2m.cn/submit.php"],
            },
            "sensitive_fields": ["idcard", "bankcard"],
        },
        text="2026年度养老补贴申领，请填写身份证号与银行卡号",
    )
    assert sig.is_elder
    assert any("安全核验" in a for a in sig.hits["action"])


def test_decoy_alone_does_not_make_a_page_elder():
    """只有诱饵没有受众指向：不判涉老。

    否则每个用 Cloudflare 的站、每个「请稍候」跳转页都会被算成涉老。
    受众指向仍然是必要条件。
    """
    from silver_sentinel.elder import assess as assess_elder

    sig = assess_elder(
        {"decoy": {"is_decoy": True, "kind": "security_check", "downstream": ["https://x.cn/2"]}},
        text="正在检测您的设备环境，请稍候",
    )
    assert not sig.is_elder
    assert sig.reason == "无受众指向"


def test_decoy_node_stays_in_candidate_even_with_low_score(fresh_db):
    """诱饵 + 有去向 → 候选，不因分数低沉到冷存。

    冷存等于再也不看，而入口是会换地址的。
    """
    from silver_sentinel.models import Asset
    from silver_sentinel.triage import decide

    asset = Asset(
        kind="url", value="https://entry.cn/", normalized="https://entry.cn/",
        score=5.0, verdict="insufficient", tier="candidate", meta={},
    )
    decision = decide(
        asset,
        facts={
            "decoy": {
                "is_decoy": True,
                "kind": "security_check",
                "weight": 3,
                "downstream": ["https://d7k2m.cn/submit.php"],
                "reason": "核验诱饵页，真实内容在下一跳",
            }
        },
    )
    assert decision.tier == "candidate"
    assert "分发节点" in "；".join(decision.reasons)


def test_waf_block_does_not_affect_triage():
    """被墙了就说被墙了，不要据此判低分。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.triage import decide

    asset = Asset(
        kind="url", value="https://blocked.cn/", normalized="https://blocked.cn/",
        score=5.0, verdict="insufficient", tier="candidate", meta={},
    )
    decision = decide(
        asset,
        facts={"decoy": {"blocked_by": "Cloudflare 挑战", "is_decoy": False}},
    )
    # 不因为 WAF 页就把分数当结论，仍按常规路径走（低分 → 冷存）
    assert decision.tier == "cold"
    assert not any("诱饵" in r for r in decision.reasons)


def test_cross_site_post_target_counts_as_exit():
    """按钮没点中时的兜底：XHR 已经打到跨域提交地址，那就是去向。

    暖阳那类的表单地址写在 JS 里，`_follow_cta` 认不出「点我」这种文案，
    但运行时请求记录里已经有 `api.php`。不用再抓一次页面。
    """
    sig = decoy.assess(
        html="<html><body>正在检测您的设备环境，请稍候</body></html>",
        text="正在检测您的设备环境，请稍候",
        title="安全检测中心",
        status=200,
        final_url="https://26537.net/",
        request_host="26537.net",
        post_targets=["https://d7k2m.cn/api.php", "https://26537.net/track"],
    )
    assert sig.is_decoy
    assert sig.kind == "security_check"
    assert any("d7k2m.cn" in u for u in sig.downstream)
    assert not any("26537.net/track" in u for u in sig.downstream)


def test_analytics_post_is_not_an_exit():
    """埋点不是去向。

    线上实测：三个 virsms 站被判成核验诱饵，而它们唯一的「XHR 目标」
    是 google-analytics.com/g/collect。把埋点当去向，等于把所有装了 GA
    的短页面都判成诱饵。
    """
    sig = decoy.assess(
        html="<html><body>正在检测您的设备环境，请稍候</body></html>",
        text="正在检测您的设备环境，请稍候",
        title="安全检测中心",
        status=200,
        final_url="https://virsms0028.cc/",
        request_host="virsms0028.cc",
        post_targets=["https://www.google-analytics.com/g/collect?v=2&tid=G-XXX"],
    )
    assert not sig.is_decoy
    assert not sig.downstream


def test_download_hint_only_counts_href():
    """整页搜 'download' 会把脚本和文案算成入口，必须限定在链接里。"""
    html = ('<html><body>正在安全检测，请稍候'
            '<script>var msg="please download our app";</script></body></html>')
    sig = decoy.assess(html=html, text="正在安全检测，请稍候", title="安全检测中心",
                       status=200, final_url="https://x.cn/", request_host="x.cn")
    assert not sig.is_decoy


def test_download_shell_is_a_decoy():
    """暖邻 26537.net 的真实形态：127 字正文 + 5 个 /go/download 跳板。

    它不伪装成任何东西，也没有核验词——就是一张「点这里下载」的皮。
    这种页面前几版全都判成「未发现特征」，于是 84 条涉老里最像分发入口的
    那一条一直躺在候选池。
    """
    sig = decoy.assess(
        html="<html><body><h1>暖邻</h1>点击下载<a href='/go/download1'>安卓版</a></body></html>",
        text="暖邻 点击下方按钮下载安装",
        title="暖邻",
        status=200,
        final_url="https://26537.net/download",
        request_host="26537.net",
        apk_links=[f"https://26537.net/go/download{i}" for i in range(1, 6)],
    )
    assert sig.is_decoy
    assert sig.kind == "download_shell"
    assert sig.weight == 3


def test_normal_software_site_with_download_is_not_decoy():
    """正规软件官网也有下载按钮，但会写功能介绍，正文不会只有 127 字。"""
    body = ("某某工具箱 官方下载。支持 Windows / macOS / Linux，"
            "功能介绍：批量重命名、文件校验、磁盘分析。客服邮箱 support@example.com。"
            "版权所有 © 2020-2026 某某科技。京ICP备00000000号。") * 4
    sig = decoy.assess(
        html=f"<html><body><p>{body}</p><a href='/download/app.exe'>下载</a></body></html>",
        text=body,
        title="某某工具箱 - 官方下载",
        status=200,
        final_url="https://tool.example.com/",
        request_host="tool.example.com",
        apk_links=["https://tool.example.com/download/app.exe"],
    )
    assert not sig.is_decoy
