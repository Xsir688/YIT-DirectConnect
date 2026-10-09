# -*- coding: utf-8 -*-
"""离线自检：URL 复刻、JSONP 解析、DPAPI 加解密。不联网。"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import yit_connect as Y  # noqa: E402

FAILED = []


def check(name, got, want):
    ok = got == want
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if not ok:
        print("   期望: %s" % want)
        print("   实际: %s" % got)
        FAILED.append(name)


# ---- 1. 抓包原始 URL（逐字节比对基准）
CAPTURED = (
    "http://10.10.10.5/drcom/login?callback=dr1005&DDDDD=26134628&upass=079235"
    "&0MKKey=123456&R1=0&R2=&R3=0&R6=0&para=00&v4ip=172.26.254.77&v6ip="
    "&captcha=&terminal_type=1&lang=zh-cn&login_t=0&js_status=0&is_page=1"
    "&is_page_new=5895&rcn=jcc5OmVg&program_index=l5WrUG1761298833"
    "&page_index=1ZWET41761298851&jsVersion=4.2.2&v=7403&lang=zh"
)

built = Y.build_login_url("26134628", "079235", "172.26.254.77")
check("登录 URL 与抓包逐字节一致", built, CAPTURED)

# ---- 2. 动态参数覆盖
dyn = Y.build_login_url("26134628", "079235", "10.1.2.3", {"rcn": "AAA"})
check("动态参数可覆盖", "&rcn=AAA&" in dyn, True)
check("v4ip 可覆盖", "&v4ip=10.1.2.3&" in dyn, True)

# ---- 3. 特殊字符转义（账号带 @ 后缀的情况）
esc = Y.build_login_url("26134628@telecom", "p w d", "1.2.3.4")
check("账号 @ 不被破坏", "DDDDD=26134628%40telecom" in esc or
      "DDDDD=26134628@telecom" in esc, True)

# ---- 4. JSONP 解析
body = ('dr1005({"result": 1, "aolno": 9494, "v46ip": "172.26.254.77", '
        '"olmac": "30f6ef6abf67", "uid": "26134628@telecom", "NID": ""})')
data, _txt = Y.parse_result(body.encode("gbk"))
check("成功响应解析 result", data and data.get("result"), 1)
check("成功响应解析 uid", data.get("uid"), "26134628@telecom")

failbody = 'dr1005({"result": 0, "msg": "密码错误"})'
d2, _ = Y.parse_result(failbody.encode("gbk"))
check("失败响应解析 msg", d2.get("msg"), "密码错误")

check("非 JSONP 内容不炸", Y.parse_result(b"<html>hello</html>")[0], None)

# ---- 5. DPAPI 往返（写到临时目录，不碰真实配置）
import tempfile  # noqa: E402
tmpdir = tempfile.mkdtemp(prefix="yit_test_")
orig_dir, orig_file = Y.CONFIG_DIR, Y.CONFIG_FILE
Y.CONFIG_DIR = tmpdir
Y.CONFIG_FILE = os.path.join(tmpdir, "config.dat")
try:
    Y.save_config("26134628", "079235")
    raw = open(Y.CONFIG_FILE, "rb").read()
    check("配置已加密（无明文密码）", b"079235" not in raw, True)
    cfg = Y.load_config()
    check("DPAPI 往返 account", cfg and cfg["account"], "26134628")
    check("DPAPI 往返 password", cfg and cfg["password"], "079235")
finally:
    Y.CONFIG_DIR, Y.CONFIG_FILE = orig_dir, orig_file
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

# ---- 6. 控制台编码兼容（回归：曾因写死 GBK 导致「找不到无线网卡」）
for enc in ("utf-8", "gbk"):
    sample = "名称                   : WLAN 2"
    check("_decode_console 支持 %s" % enc,
          Y._decode_console(sample.encode(enc)), sample)

# ---- 7. netsh 真实输出解析（依赖本机无线网卡，失败不算错误）
try:
    iface, state, ssid = Y.wifi_state()
    print("[INFO] wifi_state() = %r" % ((iface, state, ssid),))
    check("能解析出无线接口名", bool(iface), True)
except Exception as e:
    print("[INFO] 跳过 wifi_state 检查：%r" % e)

# ---- 8. 失败原因翻译（用实测抓到的原始返回，不是编的）
REAL_FAIL = (b'     dr1005({"result":0,"wopt":0,"msg":1,"uid":"26134628",'
             b'"ss5":"172.26.254.77","msga":"clientip online"})   ')
d, t = Y.parse_result(REAL_FAIL)
msg = Y.describe_failure(d, t)
check("识别出「已经在线」", "已经在线" in msg, True)
check("给出可操作的下一步", "注销" in msg, True)
check("不再把错误码当消息（旧 bug）", msg.strip() == "1", False)
check("附带原始 msga 便于排查", "msga='clientip online'" in msg, True)

d2, _ = Y.parse_result(b'dr1005({"result":0,"msg":7,"msga":"weird thing"})')
m2 = Y.describe_failure(d2, "")
check("未知原因原样展示", "weird thing" in m2, True)

d3, _ = Y.parse_result(b'dr1005({"result":0,"msg":3})')
m3 = Y.describe_failure(d3, "")
check("门户不说原因时也有提示", "没说明原因" in m3, True)

m4 = Y.describe_failure(None, "<html>Internal Server Error</html>")
check("无法解析时有提示", "无法解析" in m4, True)

# ---- 9. 本机 IP 探测
ip = Y.local_ip_toward()
print("[INFO] local_ip_toward() = %r" % ip)

# ---- 10. 注销相关（换号要用）
import re  # noqa: E402
mac = Y.read_mac()
print("[INFO] read_mac() = %r" % mac)
check("能读到网卡 MAC 且是 12 位十六进制",
      bool(re.fullmatch(r"[0-9A-F]{12}", mac)), True)
check("注销在 801 端口（登录在 80，两者不同）", Y.LOGOUT_PORT, 801)
check("注销路径是 /eportal/portal/mac/unbind",
      Y.LOGOUT_PATH, "/eportal/portal/mac/unbind")
check("识别「IP 已在线」这种拒绝",
      Y.is_client_online({"result": 0, "msga": "clientip online"}), True)
check("别的错误不误判为已在线",
      Y.is_client_online({"result": 0, "msga": "password error"}), False)

# ---- 11. 自助服务「腾名额」（设备数满了才会用到）
check("自助服务在 8080，跟门户(80)不是一台机器", Y.SELF_PORT, 8080)
check("自助服务基址", Y.SELF_BASE, "http://10.10.10.8:8080/Self")
check("密码 md5 与抓包一致",
      Y.md5_hex("079235"), "d86532d38ad5b54fd0cfe3067f452c80")

# 登录表单逐字节复刻。注意 checkcode 是**页面里的隐藏令牌**、code 是那个
# 看得见的验证码框 —— 实测 code 留空即可，所以永远发 code=。
check("自助服务登录表单逐字节一致",
      Y.self_login_form("26134628", "079235", "3099"),
      "foo=&bar=&checkcode=3099&account=26134628"
      "&password=d86532d38ad5b54fd0cfe3067f452c80&code=")
check("表单里 code 永远是空的（不需要人填验证码）",
      Y.self_login_form("a", "b", "1234").endswith("&code="), True)

# 隐藏令牌要从登录页里抠出来，抠错了登录必失败且服务器不给任何提示
LOGIN_HTML = (
    '<div style="position: absolute;left: -1000px;top: -100px">'
    '<input type="text" name="foo"/> <input type="password" name="bar"/>'
    ' <input\n   type="hidden" name="checkcode" value="1164">'
    '</div>'
)
check("能从登录页抠出隐藏令牌", Y.parse_checkcode(LOGIN_HTML), "1164")
check("页面里没令牌时返回空串不炸", Y.parse_checkcode("<html></html>"), "")
check("空输入不炸", Y.parse_checkcode(None), "")

# 踢设备的路径是 tooffline（两个 o）。写成 toffline 会 404，
# 而服务器对不存在的 sessionid 也照样回 success:true，光看返回值会被骗。
import inspect as _inspect  # noqa: E402
_src = _inspect.getsource(Y.SelfService.kick)
check("踢设备打的是 /dashboard/tooffline", "/dashboard/tooffline?" in _src, True)
check("不再用拼错的 toffline", "/dashboard/toffline?" in _src, False)

# 什么时候**不**该去踢设备：明摆着是账号密码问题，去了也白去，
# 还白让用户填一次验证码
check("密码错 -> 不折腾踢设备",
      Y.looks_like_bad_credentials({"msga": "password error"}), True)
check("账号不存在 -> 不折腾踢设备",
      Y.looks_like_bad_credentials({"msga": "userid error"}), True)
check("设备数满 -> 才去踢设备",
      Y.looks_like_bad_credentials({"msga": "inuse, login again"}), False)
check("门户没回话 -> 不算账号密码问题",
      Y.looks_like_bad_credentials(None), False)

# 挑谁踢：抓包拿到的真实设备列表（iqoo-15 手机，不是本机）
REAL_DEVICES = [{
    "brasid": "1", "downFlow": "95434", "hostName": "iqoo-15",
    "ip": "172.26.188.16", "loginTime": "2026-09-10 18:39:46",
    "mac": "4ED02FBB18DD", "sessionId": "54100",
    "terminalType": "#移动终端", "upFlow": "0", "useTime": "730",
    "userId": 700001094,
}]
MY_MAC = "30F6EF6ABF67"          # 本机网卡（netsh 读出来就是这个）
v, _why = Y.pick_victim(REAL_DEVICES, MY_MAC)
check("从真实列表里挑出该踢的设备", v and v["sessionId"], "54100")

# 最重要的一条：列表里只有本机时，绝不动手
v2, why2 = Y.pick_victim([{"mac": MY_MAC, "hostName": "本机",
                           "ip": "1.1.1.1", "sessionId": "9"}], MY_MAC)
check("列表里只有本机 -> 坚决不踢", v2, None)
check("并且说明为什么不踢", "不踢自己" in why2, True)

# 两台都是别人的，也只踢一台（挑第一台），不搞连坐
v3, _ = Y.pick_victim([{"mac": "AAAAAAAAAAAA", "sessionId": "a"},
                       {"mac": "BBBBBBBBBBBB", "sessionId": "b"}], MY_MAC)
check("只踢一台", v3["sessionId"], "a")
check("MAC 大小写不敏感",
      Y.pick_victim([{"mac": "4ed02fbb18dd"}], MY_MAC)[0] is not None, True)
check("列表为空不炸", Y.pick_victim([], MY_MAC)[0], None)
check("设备没有 mac 字段也不炸",
      Y.pick_victim([{"sessionId": "x"}], MY_MAC)[0]["sessionId"], "x")

# 踢完怎么判断成没成。踩过的坑：服务器拆会话要 1 秒多，立刻复查会看到设备
# 还挂着，于是第一次点击明明已经踢成功，却被判成失败、白弹一个错误框。
ONLINE_LIST = [{"mac": "4ED02FBB18DD", "sessionId": "54100", "hostName": "iqoo-15"}]
check("列表里还有这个会话 -> 还在", Y.still_online(ONLINE_LIST, "54100"), True)
check("列表里没有这个会话 -> 没了", Y.still_online(ONLINE_LIST, "7062"), False)
check("列表读不到 -> 不知道（不能当成踢成功）", Y.still_online(None, "54100"), None)
check("sessionId 数字/字符串都能比",
      Y.still_online([{"sessionId": 54100}], "54100"), True)
check("空列表 -> 没了", Y.still_online([], "54100"), False)
check("踢完不会立刻下结论（有等待轮次）",
      "time.sleep" in _inspect.getsource(Y.Flow.try_free_a_slot), True)

# ---- 12. 别人电脑上必踩的两个坑（自己电脑 Wi-Fi 一直连着，永远碰不到）

# 坑一：关联上 SSID ≠ 拿到 IP。没 IP 就发请求 -> WinError 10065
# 「认证服务器无响应」，用户完全不知道怎么办。
_real_ip = Y.local_ip_toward
Y.local_ip_toward = lambda *a, **k: "172.26.254.77"
check("拿到 IP 就立刻返回，不白等", Y.wait_ip(3), "172.26.254.77")

Y.local_ip_toward = lambda *a, **k: ""
_t0 = time.time()
check("一直拿不到 IP -> 超时返回空串", Y.wait_ip(1.0), "")
check("确实等满了才放弃（不是发一次就死心）", time.time() - _t0 >= 0.9, True)
Y.local_ip_toward = _real_ip

_src_run = _inspect.getsource(Y.Flow.run)
check("连上之后会等 IP，而不是直接发请求",
      "wait_ip(" in _src_run, True)
check("等不到 IP 时给的是人话，不是 WinError",
      "一直没分到 IP" in _src_run, True)

# 坑二：门户说 clientip online，但开头已确认「上不了网」——那是僵死会话，
# 必须清掉。原来要求 force 才肯清，导致别人电脑/换机重装永远登不进去。
check("clientip online 不再要求 force 才处理",
      "is_client_online(data)" in _src_run and "force and is_client_online" not in _src_run,
      True)
check("门户没应答时会重试一次", "门户没应答" in _src_run, True)

# ---- 12b. 什么时候才去踢设备：**只有名额满了**
# 用户的原话：「第一次尝试登不进去发现设备满了再执行去自助踢设备，
# 如果第一次能直接进去的话就不需要了」。所以判据必须是「门户说了名额满」，
# 不能是「只要不是密码错就踢」—— 后者会把 mac error / ip_exist 也拉去跑一趟，
# 还会白踢掉用户另一台设备。
check("认得出「名额满了」（实测原话）",
      Y.looks_like_device_full({"msga": "inuse, login again"}), True)
check("密码错不算名额满",
      Y.looks_like_device_full({"msga": "password error"}), False)
check("clientip online 不算名额满",
      Y.looks_like_device_full({"msga": "clientip online"}), False)

check("名额满了 -> 去踢",
      Y.should_try_free_slot({"msga": "inuse, login again"}), True)
check("密码错 -> 不去踢",
      Y.should_try_free_slot({"msga": "password error"}), False)
check("账号不存在 -> 不去踢",
      Y.should_try_free_slot({"msga": "userid error"}), False)
check("MAC 绑定不符 -> 不去踢（踢谁都没用）",
      Y.should_try_free_slot({"msga": "mac error"}), False)
check("IP 被占用 -> 不去踢（跟名额无关）",
      Y.should_try_free_slot({"msga": "ip_exist"}), False)
check("clientip online -> 不去踢（前面已注销过旧会话）",
      Y.should_try_free_slot({"msga": "clientip online"}), False)
check("门户没回话 -> 不去踢",
      Y.should_try_free_slot(None), False)
check("门户没说原因 -> 兜底还是去踢",
      Y.should_try_free_slot({"result": 0, "msg": 7}), True)
check("没见过的说法 -> 兜底还是去踢",
      Y.should_try_free_slot({"msga": "something brand new"}), True)

_src_tfs = _inspect.getsource(Y.Flow.run)
check("Flow.run 用的是明确判据，不是「只要不是密码错就踢」",
      "should_try_free_slot(data)" in _src_tfs and
      "not looks_like_bad_credentials(data)" not in _src_tfs, True)

# 整条「腾名额」路不再需要用户参与 —— 验证码那套已经删干净了
check("有 warm_up_captcha（必须空跑一次，否则登录被打回）",
      callable(getattr(Y.SelfService, "warm_up_captcha", None)), True)
check("旧的 captcha() 已删除", hasattr(Y.SelfService, "captcha"), False)
check("登录不再收验证码参数",
      list(_inspect.signature(Y.SelfService.login).parameters),
      ["self", "account", "password"])
check("Flow 不再收 ask_captcha",
      "ask_captcha" in _inspect.signature(Y.Flow.__init__).parameters, False)
check("App 不再有验证码弹窗",
      hasattr(Y.App, "ask_captcha"), False)

# ---- 13. 连通性探测（假成功 / 判断太急）
# 现成的 http_get 会真发请求，测试里换成假的，别联网。
_real_get = Y.http_get


def _fake_get(st, body, exc=None):
    def f(url, timeout=6, **kw):
        if exc:
            raise exc
        return st, body
    return f


Y.http_get = _fake_get(204, b"")
check("204 空响应 -> 通", Y.probe_internet()[0], True)

Y.http_get = _fake_get(200, "<html>请先登录</html>".encode("utf-8"))
ok, why = Y.probe_internet()
check("被劫持到门户页 -> 不通", ok, False)
check("说明里写清了期望值（不是只甩一句「不通」）", "期望 204" in why, True)

Y.http_get = _fake_get(0, b"", exc=OSError("unreachable"))
check("没人应答 -> 不通", Y.probe_internet()[0], False)
check("区分「连不上」和「回了但不对」", "连不上" in Y.probe_internet()[1], True)

# 下面是查源码/查系统设置的，得先把真的 http_get 装回去 —— 否则 getsource
# 读到的是上面那些测试替身，断言会假过或假挂。
Y.http_get = _real_get

# 日志里只写「URLError」等于没写：系统代理拦了和 DNS 挂了报的都是它，
# 处理方式却完全不同。必须带上原因原文。
check("异常原因要带上，不能只写类型名",
      Y.short_err(Exception("<urlopen error [Errno 11001] getaddrinfo failed>")),
      "[Errno 11001] getaddrinfo failed")
check("没有 urllib 包装时原样输出",
      Y.short_err(Exception("boom")), "boom")
check("异常里没有文字时退回类型名",
      Y.short_err(ValueError()), "ValueError")
_src_probe = _inspect.getsource(Y.probe_internet)
check("探测失败时用的是 short_err，不是 type().__name__",
      "short_err(e)" in _src_probe and "type(e).__name__" not in _src_probe, True)

# 系统代理是「门户通了但外网上不了」的头号嫌疑：urllib 在 Windows 上会自动
# 读注册表里的系统代理，而校园网地址通常在绕过列表里 —— 于是门户 200、
# 外网 URLError。程序必须一律直连。
check("普通请求绕开系统代理（不是裸 urlopen）",
      "_OPENER.open(" in _inspect.getsource(Y.http_get), True)
check("自助服务会话也绕开系统代理",
      "ProxyHandler({})" in _inspect.getsource(Y.SelfService.__init__), True)

# 不通时要把「为什么」查清楚写进日志，别让用户来回试
_diag = Y.diagnose_network()
check("诊断会报告系统代理", any("代理" in l for l in _diag), True)
check("诊断会报告 DNS 解析结果",
      any(l.startswith("DNS ") for l in _diag), True)

# 最要紧的一条：门户记账之后 BRAS 放开闸门有延迟，第一次探不到不能立刻宣判
_calls = {"n": 0}


def _flaky(url, timeout=6, **kw):
    _calls["n"] += 1
    if _calls["n"] <= 2:                    # 前两次扑空
        return 200, b"<html>portal</html>"
    return 204, b""

Y.http_get = _flaky
_ok, _why = Y.wait_online(timeout=12)
check("头几次探不到会继续等，不立刻判死", _ok, True)
check("等通了会说明是等出来的", "等了" in _why, True)
check("确实重试了（不是撞一次就完事）", _calls["n"] > 2, True)

_calls["n"] = 0
Y.http_get = _fake_get(200, b"<html>portal</html>")
_t0 = time.time()
check("一直不通 -> 最终仍判失败", Y.wait_online(timeout=3)[0], False)
check("但确实等过一轮才放弃（不是撞一次就宣判）",
      time.time() - _t0 >= 1.4, True)
check("放弃了也没超时太久（预算有用）", time.time() - _t0 < 6, True)

Y.http_get = _real_get

_src_wait = _inspect.getsource(Y.Flow.run)  # noqa: E305
check("登录成功后按「等待」判连通，而不是立刻探一次",
      "wait_online()" in _src_wait, True)
check("报错要说清探测看到了什么",
      "外网探测不通" in _src_wait, True)

print()
print("失败项：%s" % (", ".join(FAILED) if FAILED else "无"))
sys.exit(1 if FAILED else 0)
