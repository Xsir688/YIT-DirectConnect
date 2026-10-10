# -*- coding: utf-8 -*-
"""
校园网一键直连（燕京理工学院 YIT-WIFI / Dr.COM 门户）
====================================================
双击 -> 自动切到 YIT-WIFI -> 门户认证 -> 确认外网通了 -> 进程立刻退出。

首次运行需要输入一次账号密码，之后用 Windows DPAPI 加密保存在
%APPDATA%\\YITDirectConnect\\config.dat，绑定当前 Windows 用户。

本程序只访问校园网内部的三台服务器（门户 10.10.10.5、自助服务 10.10.10.8）
和两个连通性探测点，不向任何第三方发送数据。

账号同时在线设备数满了（上限 2 台）会导致认证失败，这时程序会自动进
「用户自助服务系统」踢掉一台**不是本机**的设备腾出名额，再回来重登。
"""

import os
import re
import sys
import glob
import json
import time
import ctypes
import random
import shutil
import socket
import hashlib
import threading
import subprocess
import http.cookiejar
import urllib.parse
import urllib.request

import tkinter as tk
from tkinter import ttk, messagebox

# ------------------------------------------------------------------ 常量

APP_NAME = "YITDirectConnect"
CONFIG_DIR = os.path.join(os.environ.get("APPDATA", ""), APP_NAME)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.dat")
LOG_FILE = os.path.join(CONFIG_DIR, "run.log")     # 每次运行覆盖，排查用（绝不写密码）

SSID = "YIT-WIFI"
PORTAL = "http://10.10.10.5"
PORTAL_HOST = "10.10.10.5"
PORTAL_PORT = 80
LOGIN_PATH = "/drcom/login"
REFERER = PORTAL + "/a79.htm"

# 注销走的是**另一个服务**：801 端口下的 /eportal/portal/ ，
# 跟登录的 /drcom/ 不是一回事（这是从门户 a41.js 里挖出来的）：
#   path:       '//host/drcom/'                 <- 登录
#   portal_api: '//host:'+ep_port+'/eportal/portal/'  <- 注销
LOGOUT_PORT = 801
LOGOUT_PATH = "/eportal/portal/mac/unbind"
JS_VERSION = "4.2.2"

# 账号最多能同时在 2 台设备上，满了门户就不让登 —— 这时要去
# 「用户自助服务系统」踢掉一台占位的。那是**另一台服务器上的另一套系统**
# （Java，走 JSESSIONID），跟门户毫无关系。协议是在线抓下来、逐条实测过的：
#   GET  /Self/login/?302=EL            -> 下发 JSESSIONID + 隐藏令牌 checkcode
#   GET  /Self/login/randomCode?t=...   -> 验证码图（PNG）；**必须请求一次**，
#                                          不请求登录会被打回，**但图不用看**
#   POST /Self/login/verify             -> foo/bar/checkcode/account/md5(密码)/code
#                                          其中 checkcode 回传隐藏令牌，code 留空
#   GET  /Self/dashboard/getOnlineList  -> 在线设备数组（mac / ip / sessionId）
#   GET  /Self/dashboard/tooffline      -> 按 sessionId 踢下线（两个 o，别写错）
#
# 两个坑，都踩过：
#   · 登录的 POST **必须打裸路径 /Self/login/verify**，带上 ;jsessionid= 会被
#     当成另一个会话，永远登不进去（服务器还不给任何错误提示）
#   · tooffline 拼成 toffline（少一个 o）会 404；而且乱传 sessionid 它照样回
#     {"success":true}，所以踢完必须回头拉列表核实
SELF_HOST = "10.10.10.8"
SELF_PORT = 8080
SELF_BASE = "http://%s:%d/Self" % (SELF_HOST, SELF_PORT)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0")

# 抓包还原的登录参数（顺序保持一致）
# 值为 None 的项在运行时填充
FIXED_PARAMS = [
    ("callback", "dr1005"),
    ("DDDDD", None),            # 账号
    ("upass", None),            # 密码
    ("0MKKey", "123456"),
    ("R1", "0"),
    ("R2", ""),
    ("R3", "0"),
    ("R6", "0"),
    ("para", "00"),
    ("v4ip", None),             # 本机通往门户的 IP
    ("v6ip", ""),
    ("captcha", ""),
    ("terminal_type", "1"),
    ("lang", "zh-cn"),
    ("login_t", "0"),
    ("js_status", "0"),
    ("is_page", "1"),
    ("is_page_new", "5895"),
    ("rcn", "jcc5OmVg"),
    ("program_index", "l5WrUG1761298833"),
    ("page_index", "1ZWET41761298851"),
    ("jsVersion", "4.2.2"),
    ("v", "7403"),
    ("lang", "zh"),
]

# 可能是页面会话令牌，兜底时要重新取
DYNAMIC_KEYS = ("rcn", "program_index", "page_index", "jsVersion")


# ------------------------------------------------------------------ 运行日志

def log_start():
    """每次启动重置日志。"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("=== 校园网直连 运行日志 %s ===\n"
                    % time.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        pass


def log_line(msg):
    """追加一行日志。绝不写密码 —— 调用方自己保证。"""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("%s  %s\n" % (time.strftime("%H:%M:%S"), msg))
    except Exception:
        pass


# ------------------------------------------------------------------ DPAPI 加解密

class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, decrypt: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    fn = ctypes.windll.crypt32.CryptUnprotectData if decrypt \
        else ctypes.windll.crypt32.CryptProtectData
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0,
              ctypes.byref(blob_out)):
        raise OSError("DPAPI 调用失败")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def save_config(account: str, password: str, uid: str = None) -> None:
    """uid 是门户给的带运营商标识的账号（如 26134628@telecom），注销时要用。"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    data = {"account": account, "password": password}
    if uid:
        data["uid"] = uid
    with open(CONFIG_FILE, "wb") as f:
        f.write(_dpapi(json.dumps(data).encode("utf-8"), decrypt=False))


def load_config():
    if not os.path.isfile(CONFIG_FILE):
        return None
    try:
        raw = _dpapi(open(CONFIG_FILE, "rb").read(), decrypt=True)
        cfg = json.loads(raw.decode("utf-8"))
        if cfg.get("account") and cfg.get("password"):
            return cfg
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ 网络命令行

def _decode_console(raw: bytes) -> str:
    """netsh 等系统命令的输出编码因机器而异（本机是 UTF-8，很多机器是 GBK）。

    必须**先试 UTF-8**：UTF-8 严格解码遇到 GBK 中文会直接报错，
    而 GBK 却能"成功"解码 UTF-8 的中文并产出乱码 —— 顺序反了就静默出错。
    """
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


_CNW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # 执行命令时不闪黑框


def _run(cmd):
    """不弹黑框地执行命令，返回解码后的 stdout。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=30,
                           creationflags=_CNW)
        return _decode_console(p.stdout or b"")
    except Exception:
        return ""


# ------------------------------------------------------------------ 后台清理

def self_exe_name():
    """打包成 exe 运行时返回自己的进程名；从源码运行时返回 None。

    这一点很关键：从源码跑的时候进程名是 python.exe，
    按名字去杀会误伤用户其他 Python 程序，所以那种情况直接不杀。
    """
    if getattr(sys, "frozen", False):
        return os.path.basename(sys.executable)
    return None


def pick_pids_to_kill(listing, protect, name):
    """从 tasklist 的 CSV 里挑出该结束的 PID。抽成纯函数是为了能单测。

    即便 tasklist 已经按名字过滤过，这里仍然**再核对一次进程名**：
    宁可不杀，也绝不误伤无关进程。
    """
    pids = []
    for row in listing.splitlines():
        m = re.search(r'"([^"]*\.exe)","(\d+)"', row)
        if not m:
            continue
        if m.group(1).lower() != name.lower():
            continue
        pid = int(m.group(2))
        if pid not in protect:
            pids.append(pid)
    return pids


def kill_other_instances():
    """结束本程序的其他实例，返回结束的个数。

    必须保护两个 PID：
      · 自己 —— 交给 _quit() 正常退出
      · 自己的引导父进程 —— PyInstaller 单文件模式下**由它负责删除临时目录**，
        杀了它，自己的 _MEI 反而会永久留在磁盘上，与「清理干净」正好相反。
    """
    name = self_exe_name()
    if not name:
        return 0
    protect = {os.getpid(), os.getppid()}
    listing = _run(["tasklist", "/fi", "imagename eq " + name, "/fo", "csv"])
    killed = 0
    for pid in pick_pids_to_kill(listing, protect, name):
        try:
            subprocess.run(["taskkill", "/f", "/pid", str(pid)],
                           capture_output=True, timeout=20, creationflags=_CNW)
            killed += 1
        except Exception:
            pass
    return killed


def sweep_mei():
    """清掉 PyInstaller 的临时解压残留（跳过自己正在用的那份），返回清掉的个数。"""
    temp = os.environ.get("TEMP") or os.environ.get("LOCALAPPDATA") or ""
    if not temp or not os.path.isdir(temp):
        return 0
    mine = getattr(sys, "_MEIPASS", "") or ""
    mine = os.path.normcase(os.path.abspath(mine)) if mine else ""
    swept = 0
    for d in glob.glob(os.path.join(temp, "_MEI*")):
        if mine and os.path.normcase(os.path.abspath(d)) == mine:
            continue          # 自己正在用的，删了会当场崩
        try:
            shutil.rmtree(d)
            swept += 1
        except Exception:
            pass              # 被占用就跳过，不强求
    return swept


def wifi_state():
    """返回 (接口名, 状态, 当前SSID)。"""
    out = _run(["netsh", "wlan", "show", "interfaces"])
    iface = state = ssid = None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"^名称\s*:\s*(.+)$", line)
        if m and iface is None:
            iface = m.group(1).strip()
            continue
        m = re.match(r"^状态\s*:\s*(.+)$", line)
        if m:
            state = m.group(1).strip()
            continue
        m = re.match(r"^SSID\s*:\s*(.+)$", line)
        if m:
            ssid = m.group(1).strip()
    return iface, state, ssid


def is_connected(ssid=None):
    _, state, cur = wifi_state()
    if not state or "已连接" not in state:
        return False
    return ssid is None or cur == ssid


def connect_wifi(iface):
    _run(["netsh", "wlan", "connect", "name=" + SSID, "interface=" + iface])


def wait_connected(timeout=15.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_connected(SSID):
            return True
        time.sleep(0.5)
    return False


def local_ip_toward(host=PORTAL_HOST, port=PORTAL_PORT):
    """本机通往门户所用的 IP，即门户眼中的 v4ip。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


def wait_ip(timeout=20.0):
    """等本机真的拿到一个能通往门户的 IP，返回 IP（超时返回空串）。

    **关联上 SSID ≠ 拿到 IP**：DHCP 有时要好几秒。这时候就往门户发请求的话，
    因为压根没有路由，会撞上 WinError 10065（主机无法连接），报出来是一句
    没人看得懂的「认证服务器无响应」。别人电脑上第一次点必然失败就是这么来的
    —— 自己电脑 Wi-Fi 一直连着，永远碰不到这个坑。
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        ip = local_ip_toward()
        if ip:
            return ip
        time.sleep(0.5)
    return ""


def read_mac():
    """读无线网卡物理地址，返回大写无分隔符形式（如 30F6EF6ABF67）。"""
    out = _run(["netsh", "wlan", "show", "interfaces"])
    m = re.search(r"^\s*(?:物理地址|Physical address)\s*:\s*(.+)$", out, re.M | re.I)
    if not m:
        return ""
    return re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()


# ------------------------------------------------------------------ HTTP

# 系统里配了代理（加速器 / VPN / Clash 之类）时，urllib 在 Windows 上会**自动
# 读注册表里的系统代理**并走它。而校园网门户必须直连 —— 代理一旦连不上，所有
# 外网请求都变成一句毫无信息量的 URLError，症状就是「门户说认证成功，但实际
# 上不了网」；偏偏校园网地址常在代理的绕过列表里，于是门户和自助服务照样 200，
# 让人完全看不出是代理在捣鬼（2026-09-10 别人电脑上真实踩到）。
# 这里显式忽略系统代理，要走代理的场合本来也不该用这个程序。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_get(url, referer=None, timeout=8):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
    })
    if referer:
        req.add_header("Referer", referer)
    with _OPENER.open(req, timeout=timeout) as r:
        return r.status, r.read()


def decode_body(body: bytes) -> str:
    for enc in ("gbk", "utf-8", "gb18030"):
        try:
            return body.decode(enc)
        except Exception:
            continue
    return body.decode("utf-8", errors="replace")


PROBES = (
    ("http://connect.rom.miui.com/generate_204", 204, None),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft"),
)


def short_err(e):
    """把异常压成一行短话。

    原来这里只记 `type(e).__name__`，写出来就是一句「URLError」—— 等于没说，
    因为「系统代理拦了」和「DNS 挂了」报的都是 URLError，处理方式却完全不同。
    必须带上原因原文（如 `[Errno 11001] getaddrinfo failed`）才能定位。
    """
    txt = str(e).strip()
    m = re.match(r"<urlopen error (.*)>\s*$", txt)
    if m:
        txt = m.group(1).strip()
    return txt[:90] or type(e).__name__


def diagnose_network():
    """外网探测不通时把能查的都查一遍，返回要写进日志的若干行。

    光知道「不通」没用，得知道**为什么**：系统代理是什么、探测域名能不能解析。
    下次看日志就能直接定位，不用再让用户来回试。
    """
    lines = []
    try:
        proxies = urllib.request.getproxies()
    except Exception as e:
        proxies = {"(读取失败)": short_err(e)}
    lines.append("系统代理: %s" % (proxies or "无"))

    for url, _expect, _needle in PROBES:
        host = url.split("/")[2]
        try:
            infos = socket.getaddrinfo(host, 80)
            ips = sorted({i[4][0] for i in infos})
            lines.append("DNS %s -> %s" % (host, ", ".join(ips[:3])))
        except Exception as e:
            lines.append("DNS %s 解析失败: %s" % (host, short_err(e)))
    return lines


def probe_internet(timeout=6):
    """探一次外网，返回 (通没通, 说明)。说明既给日志也给用户看。

    说明里要能区分两种「不通」：**压根没人应答**（没网 / 没路由）和
    **有人应答但不是我们要的东西**（被劫持到门户页）。排查时这两者
    天差地别，混成一句「上不了网」等于没写。
    """
    said = []
    for url, expect, needle in PROBES:
        host = url.split("/")[2]
        try:
            st, body = http_get(url, timeout=timeout)
        except Exception as e:
            said.append("%s 连不上（%s）" % (host, short_err(e)))
            continue
        if st != expect:
            # 门户劫持最典型：没放行时它会回 200 + 登录页，而不是 204
            said.append("%s 回了 HTTP %s（期望 %s）" % (host, st, expect))
            continue
        if needle and needle not in body:
            said.append("%s 内容不对" % host)
            continue
        return True, "%s 正常" % host
    return False, "；".join(said) or "没有可用的探测点"


def is_online(timeout=6) -> bool:
    """真正判断能不能上外网 —— 门户经常"假成功"，必须实测。"""
    return probe_internet(timeout)[0]


def wait_online(timeout=12.0, interval=1.5):
    """等外网真的通。返回 (通没通, 说明)。

    门户回 result=1 只说明**它记账了**，BRAS 那边放开闸门还要一口气的工夫
    （而且越忙越慢）。上一版登录一成功就立刻探一次，扑空就宣判
    「门户说成功了，但实际上不了网」—— 而自助服务里明明白白记着这条上线
    记录，说明其实已经连上了（2026-09-10 别人电脑上真实踩到）。

    跟「踢完别立刻复查列表」是同一类毛病：**判断太急**。这里按
    1.5/3/4.5/6 秒的节奏多探几次，任意一次通了就算成功。
    """
    t0 = time.time()
    ok, why = probe_internet(timeout=4)
    if ok:
        return True, why
    for wait in (1.5, 3.0, 4.5, 6.0):
        if time.time() - t0 + wait > timeout:
            break
        time.sleep(wait)
        ok, why = probe_internet(timeout=4)
        if ok:
            return True, "%s（等了 %.0f 秒才通）" % (why, time.time() - t0)
    return False, why


# ------------------------------------------------------------------ 门户认证

def build_login_url(account, password, v4ip, dynamic=None):
    pairs = []
    for key, val in FIXED_PARAMS:
        if key == "DDDDD":
            val = account
        elif key == "upass":
            val = password
        elif key == "v4ip":
            val = v4ip
        if dynamic and key in dynamic:
            val = dynamic[key]
        pairs.append((key, val))
    query = urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote)
    return PORTAL + LOGIN_PATH + "?" + query


# 门户 msga 字段的解读。已实测确认的只有第一条，其余是 Dr.COM 常见码，
# 万一对不上，错误框里会同时把原始返回打出来，随时可以校正。
PORTAL_MSGA = {
    "clientip online": (
        "当前网络已经在线",
        "这个 IP 上还有账号没下线，门户直接拒绝了新登录（此时它根本不校验账号密码）。\n"
        "要换账号：先在浏览器打开 http://10.10.10.5 点「注销」，或断开 WiFi 重连，然后再试。"),
    "password error": ("密码错误", "请检查密码有没有输错。"),
    "userid error": ("账号不存在", "请检查账号有没有输错。"),
    "userid error1": ("账号不存在", "请检查账号有没有输错。"),
    "userid error2": ("账号与所选运营商不匹配", "该账号只能通过开户的运营商登录。"),
    "userid error3": ("账号已停机", "请联系校园网络中心。"),
    "no this user": ("账号不存在", "请检查账号有没有输错。"),
    "mac error": ("网卡 MAC 与该账号绑定不符", "这个账号绑定了别的设备，需要先解绑。"),
    "ip_exist": ("该 IP 已被占用", "稍等片刻，或断开 WiFi 重连后再试。"),
}


def describe_failure(data, txt):
    """把门户的返回翻译成能看懂的原因。

    注意：门户用 `msga` 装原因文本，`msg` 只是个数字错误码 ——
    早期版本直接把 msg 当消息显示，才会出现「登录失败：1」这种废话。
    """
    if not data:
        raw = (txt or "").strip()[:200]
        return "门户返回了无法解析的内容：\n%s" % (raw or "(空)")

    msga = str(data.get("msga") or "").strip()
    entry = PORTAL_MSGA.get(msga.lower())

    lines = []
    if entry:
        lines.append(entry[0])
        if entry[1]:
            lines += ["", "建议：" + entry[1]]
    elif msga:
        lines.append("门户拒绝了登录：%s" % msga)
    else:
        lines.append("门户拒绝了登录，但没说明原因")

    lines += ["", "门户返回：result=%s   msg=%s   msga=%r"
              % (data.get("result"), data.get("msg"), msga)]
    return "\n".join(lines)


def parse_result(body: bytes):
    """解析 JSONP 响应 dr1005({...})，返回 (字典或None, 原始文本)。"""
    txt = decode_body(body)
    m = re.search(r"\{.*\}", txt, re.S)
    if not m:
        return None, txt
    try:
        return json.loads(m.group(0)), txt
    except Exception:
        return None, txt


def refresh_dynamic():
    """兜底：重新请求门户页，尝试取回会过期的会话参数。"""
    try:
        st, body = http_get(PORTAL + "/a79.htm", timeout=8)
        html = decode_body(body)
    except Exception:
        return None
    found = {}
    for key in DYNAMIC_KEYS:
        m = re.search(
            key + r"""["']?\s*[:=]\s*["']([^"'&,;\s]+)["']""", html)
        if m:
            found[key] = m.group(1)
    return found or None


def try_login(account, password, v4ip, dynamic=None):
    """发一次登录请求，返回 (是否成功, 提示文本, 门户原始返回)。"""
    # 注意：只在日志里写账号和 IP，绝不写密码，也不写含密码的完整 URL
    log_line("登录请求: account=%s  v4ip=%s  动态参数=%s"
             % (account, v4ip, bool(dynamic)))
    url = build_login_url(account, password, v4ip, dynamic)
    try:
        st, body = http_get(url, referer=REFERER, timeout=8)
    except Exception as e:
        log_line("登录请求失败: %r" % e)
        return False, "认证服务器无响应（%s）" % e, None
    data, txt = parse_result(body)
    log_line("登录返回: HTTP %s | %s" % (st, (txt or "").strip()[:280]))
    if data and data.get("result") == 1:
        log_line("=> 登录成功")
        return True, "门户报告登录成功", data
    return False, describe_failure(data, txt), data


def is_client_online(data):
    """门户是不是因为「这个 IP 已经在线」而拒绝的。"""
    return bool(data) and str(data.get("msga") or "").lower() == "clientip online"


def portal_logout(account_uid, ip, mac, timeout=8):
    """注销。返回 (是否成功, 提示)。

    Dr.COM 新门户的注销在 801 端口，且用的是 `mac/unbind` + `unbind_type=1`
    （门户自己的注销按钮就是这个）。注意跟登录的 80 端口 /drcom/ 完全分开。
    """
    if not mac:
        return False, "读不到网卡 MAC，无法注销"
    params = [
        ("callback", "dr1003"),
        ("user_account", account_uid),
        ("wlan_user_mac", mac),
        ("wlan_user_ip", ip),
        ("wlan_user_ipv6", ""),
        ("unbind_type", "1"),
        ("jsVersion", JS_VERSION),
    ]
    url = "http://%s:%d%s?%s" % (
        PORTAL_HOST, LOGOUT_PORT, LOGOUT_PATH,
        urllib.parse.urlencode(params, quote_via=urllib.parse.quote))
    log_line("注销请求: %s:%d%s  uid=%s  mac=%s  ip=%s"
             % (PORTAL_HOST, LOGOUT_PORT, LOGOUT_PATH, account_uid, mac, ip))
    try:
        st, body = http_get(url, referer=REFERER, timeout=timeout)
    except Exception as e:
        log_line("注销请求失败: %r" % e)
        return False, "注销请求失败（%s）" % e
    data, txt = parse_result(body)
    log_line("注销返回: HTTP %s | %s" % (st, (txt or "").strip()[:280]))
    if data and data.get("result") in (1, "1", "ok"):
        return True, str(data.get("msg") or "注销成功")
    return False, describe_failure(data, txt)


# --------------------------------------------------------- 自助服务（腾名额）

def md5_hex(text):
    """自助服务的登录密码要先 md5（就是它页面里 md5.js 干的活）。

    用抓到的真实请求逐字节核对过：小写十六进制、不加盐、不带时间戳。
    """
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def looks_like_bad_credentials(data):
    """门户是不是在说「账号或密码不对」。

    这种情况去自助服务踢设备纯属白费劲 —— 自助服务用的是同一套账号密码，
    密码错了它一样登不进去，还会白白让用户填一次验证码。所以直接跳过。
    """
    msga = str((data or {}).get("msga") or "").lower()
    for key in ("password", "userid", "no this user", "not exist",
                "invalid", "stopped"):
        if key in msga:
            return True
    return False


def looks_like_device_full(data):
    """门户是不是在说「这个账号的设备名额已经占满了」。

    `inuse` 是实测到的原话（`msga="inuse, login again"`，result=0、msg=1）。
    后面几个是没见过但同义的写法，留着宽进 —— 这里误判的代价只是多跑一趟
    自助服务，而漏判的代价是**用户压根连不上**，两害相权取其轻。
    """
    msga = str((data or {}).get("msga") or "").lower()
    return any(k in msga for k in ("inuse", "in use", "device", "max", "limit"))


def should_try_free_slot(data):
    """这次登录失败，值不值得跑一趟自助服务去踢设备。

    **只有名额满了才值得** —— 这也正是用户的诉求：第一次能直接进去就什么都
    不做（那本身就说明没满）。其他失败要么上面已经处理过，要么踢设备也治不了：

      · 密码 / 账号不对 -> 自助服务是同一套密码，去了也是白去
      · mac error       -> 是这个网卡绑了别的账号，踢谁都没用
      · ip_exist        -> 是这个 IP 的问题，跟名额无关
      · clientip online -> 前面已经注销过旧会话了，别人的名额不背这个锅

    唯一例外是门户**没说原因**（msga 空的、或者是没见过的说法）：这种情况
    多半还是名额满，毕竟能报的理由上面都排掉了。宁可多跑一趟，也别让用户
    干瞪眼连不上。
    """
    if data is None:
        return False                      # 门户压根没回话，踢设备无从谈起
    if looks_like_bad_credentials(data):
        return False
    if looks_like_device_full(data):
        return True
    msga = str(data.get("msga") or "").strip().lower()
    return msga not in PORTAL_MSGA        # 认得的原因 -> 别折腾；不认识的 -> 兜底


def self_login_form(account, password, checkcode):
    """自助服务登录的表单体。

    `checkcode` 是**登录页里那个隐藏 input 的值**（服务器一次性下发的反机器人
    令牌，每渲染一次页面换一个），直接从页面上抠下来就行 —— 它**不是**用户要
    填的验证码。这两个字段名长得像，实测填反了永远登不进去。

    用户看得见的验证码框其实叫 `code`，而且实测**留空就能过**（那个框在页面上
    默认还是 `hide` 状态的）。所以整条路不需要 OCR，也不需要用户参与。

    `foo` / `bar` 是页面里两个空着的诱饵字段，照抄才最稳。
    """
    return urllib.parse.urlencode({
        "foo": "", "bar": "",
        "checkcode": checkcode,
        "account": account,
        "password": md5_hex(password),
        "code": "",
    })


CHECKCODE_RE = re.compile(r'name="checkcode"\s+value="([^"]*)"')


def parse_checkcode(html):
    """从自助服务登录页里抠出隐藏令牌 checkcode；抠不到返回空串。

    抽成纯函数是为了能离线单测 —— 这东西抠错了登录必失败，而服务器
    失败时不返回任何错误文字，排起来很痛苦。
    """
    m = CHECKCODE_RE.search(html or "")
    return m.group(1) if m else ""


def still_online(devices, session_id):
    """设备列表里还能不能看到这个会话。

    三态：True 还在 / False 已经没了 / None 列表压根没读到（不知道）。
    区分 None 很重要 —— 「读不到」和「确定没了」是两回事，前者不该当成踢成功。
    """
    if devices is None:
        return None
    return any(str(d.get("sessionId")) == str(session_id) for d in devices)


def pick_victim(devices, mine):
    """从在线设备里挑一台该踢的，返回 (目标设备 或 None, 说明)。

    **永远不碰本机**：列表里只剩自己时返回 None —— 宁可这次连不上，
    也不能把自己踹下线，那比连不上更糟。
    """
    if not devices:
        return None, "在线列表是空的，没有可踢的设备"
    mine = (mine or "").upper()
    targets = [d for d in devices if str(d.get("mac", "")).upper() != mine]
    if not targets:
        return None, ("在线列表里只有本机（%s），没有别的设备可踢 —— 不踢自己"
                      % (mine or "读不到 MAC"))
    return targets[0], ""


class SelfService:
    """Dr.COM「用户自助服务系统」（10.10.10.8:8080），用来踢掉占着名额的设备。

    只在「账号设备数已满、门户不让登」时才用得上。它跟门户是两台不同的机器、
    两套不同的系统，所以这里单独维护一个 Cookie 会话（JSESSIONID），
    请求不跟门户那边混着发。
    """

    def __init__(self, log):
        self.log = log
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj),
            # 同样绕开系统代理，理由见 _OPENER 上面那段注释
            urllib.request.ProxyHandler({}))
        self.checkcode = ""      # 登录页里的隐藏令牌，登录时要原样回传

    def _open(self, url, data=None, referer=None, xhr=False, timeout=8):
        headers = {
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        }
        if xhr:
            headers["X-Requested-With"] = "XMLHttpRequest"
        if referer:
            headers["Referer"] = referer
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = "http://%s:%d" % (SELF_HOST, SELF_PORT)
        req = urllib.request.Request(url, data=data, headers=headers)
        with self.opener.open(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.read()

    def session_id(self):
        for c in self.cj:
            if c.name.upper() == "JSESSIONID":
                return c.value
        return ""

    def open_login_page(self):
        """走一遍登录页：JSESSIONID 在这一步下发，同时把隐藏令牌抠出来。

        这个令牌是一次性的，发第二次请求（哪怕是验证码图）之前拿到的才算数，
        所以必须在这里顺手记下来，不能等登录时再取。
        """
        try:
            st, _final, body = self._open(SELF_BASE + "/login/?302=EL")
        except Exception as e:
            log_line("自助服务登录页打不开: %r" % e)
            return False
        self.checkcode = parse_checkcode(decode_body(body))
        log_line("自助服务登录页: HTTP %s  JSESSIONID=%s  隐藏令牌=%s"
                 % (st, self.session_id() or "(没拿到)", self.checkcode or "(没抠到)"))
        return st == 200 and bool(self.checkcode)

    def warm_up_captcha(self):
        """空跑一次验证码图请求。

        **这一步不能省**：实测同一个会话里如果没请求过 randomCode，登录会被
        直接打回登录页；请求过之后，`code` 留空反而正常通过。图片本身不用看。
        """
        try:
            st, _u, body = self._open(
                SELF_BASE + "/login/randomCode?t=%s" % random.random(),
                referer=SELF_BASE + "/login/?302=EL")
        except Exception as e:
            log_line("预取验证码失败: %r" % e)
            return False
        log_line("预取验证码: HTTP %s  %d 字节（不解析，只为过会话状态）"
                 % (st, len(body)))
        return st == 200

    def login(self, account, password):
        """登录自助服务。返回 (是否成功, 说明)。

        成功与否看有没有被跳到 /dashboard —— 失败时服务器会原地回一个登录页，
        页面上的错误提示是空的，所以别指望从正文里读原因。
        """
        form = self_login_form(account, password, self.checkcode).encode()
        log_line("自助服务登录: account=%s 令牌=%s" % (account, self.checkcode))
        try:
            st, final, _body = self._open(
                SELF_BASE + "/login/verify", data=form,
                referer=SELF_BASE + "/login/?302=EL", timeout=10)
        except Exception as e:
            log_line("自助服务登录请求失败: %r" % e)
            return False, "自助服务没有响应"
        log_line("自助服务登录返回: HTTP %s -> %s" % (st, final))
        if "/dashboard" in final:
            return True, "自助服务登录成功"
        return False, "自助服务拒绝了登录（多半是账号密码不对）"

    def online_list(self):
        """当前账号的在线设备数组；读不到返回 None。"""
        url = SELF_BASE + "/dashboard/getOnlineList?t=%s&order=asc&_=%d" % (
            random.random(), int(time.time() * 1000))
        try:
            st, _u, body = self._open(url, referer=SELF_BASE + "/dashboard",
                                      xhr=True)
        except Exception as e:
            log_line("取设备列表失败: %r" % e)
            return None
        txt = decode_body(body)
        log_line("设备列表返回: HTTP %s | %s" % (st, txt.strip()[:300]))
        try:
            data = json.loads(txt)
        except Exception:
            return None
        return data if isinstance(data, list) else None

    def kick(self, session_id):
        """按 sessionId 把一台设备踢下线（自助服务页面上那个「注销」按钮）。

        路径是 `tooffline`（**两个 o**，页面 JS 里写的就是这个）。写成
        `toffline` 会 404，而且服务器对不存在的 sessionid 也照样回
        `{"success":true}` —— 光看返回值会被骗，所以调用方必须回头拉一次
        列表核实，这里只负责把请求发出去。
        """
        url = SELF_BASE + "/dashboard/tooffline?t=%s&sessionid=%s" % (
            random.random(), urllib.parse.quote(str(session_id)))
        log_line("踢设备请求: sessionid=%s" % session_id)
        try:
            st, _u, body = self._open(url, referer=SELF_BASE + "/dashboard",
                                      xhr=True)
        except Exception as e:
            log_line("踢设备请求失败: %r" % e)
            return False
        log_line("踢设备返回: HTTP %s | %r" % (st, decode_body(body).strip()[:200]))
        return st == 200


# ------------------------------------------------------------------ 主流程

class Flow:
    """把状态变化回报给界面。"""

    def __init__(self, log, uid=None):
        self.log = log
        self.last_uid = uid      # 形如 26134628@telecom，注销时要用

    def try_free_a_slot(self, account, password):
        """账号设备数满了 —— 进自助服务踢掉一台**不是本机**的设备腾名额。

        整条路不需要验证码、不需要用户参与：登录页会下发一个隐藏令牌，
        原样回传就能登录（可见的那个验证码框留空即可）。

        返回 (是否踢成功, 说明)。任何一步失败都老老实实把原因带回来，
        绝不硬着头皮往下走。
        """
        self.log("账号设备数可能已满，试着去自助服务腾个名额…")
        svc = SelfService(self.log)
        if not svc.open_login_page():
            return False, "自助服务（%s）打不开" % SELF_HOST
        svc.warm_up_captcha()
        ok, msg = svc.login(account, password)
        if not ok:
            return False, msg

        devices = svc.online_list()
        if devices is None:
            return False, "自助服务里读不到设备列表"
        t, why = pick_victim(devices, read_mac())
        if t is None:
            return False, why
        self.log("腾名额：踢掉 %s（%s / %s）" % (
            t.get("hostName") or "未知设备", t.get("mac"), t.get("ip")))
        if not svc.kick(t.get("sessionId")):
            return False, "踢设备的请求被拒绝了"

        # 回头拉列表核对，别光看它回 {"success":true} —— 那个返回值对不存在的
        # sessionid 照样是 true，根本不能当凭证。
        #
        # 但也不能**立刻**看：实测服务器拆会话要 1 秒多，立刻复查会看到设备
        # 还挂在上面，于是把明明已经成功的一脚判成失败，用户白点第二次。
        # 所以这里等几轮再下结论，任意一轮看不到它就算成功。
        sid = str(t.get("sessionId"))
        read_fail = False
        for wait in (0.8, 1.5, 2.5):
            time.sleep(wait)
            seen = still_online(svc.online_list(), sid)
            if seen is None:
                read_fail = True          # 这一轮没读到，再等等看
                continue
            read_fail = False
            if not seen:
                return True, "已踢掉占位设备：%s" % (t.get("hostName") or t.get("mac"))
        if read_fail:
            # 一次都没读到列表：踢的请求发出去了且没报错，只能说「大概率成了」，
            # 但不敢打包票，交给上层去重登试试
            return True, "踢设备请求已发出（没读到列表，无法核实）"
        return False, "踢是踢了，但设备还挂在上面"

    def run(self, account, password, force=False):
        """force=True 时忽略「已经在线」，强制拿新账号去认证一次（切换账号用）。"""
        self.log("检查当前网络…")
        if not force and is_online():
            log_line("已在线，无需操作")
            return True, "已经可以上网"

        iface, _state, cur = wifi_state()
        log_line("无线: 接口=%s 状态=%s SSID=%s force=%s" % (iface, _state, cur, force))
        if not iface:
            # 区分「服务没开」和「解析失败」，方便日后排查
            raw = (_run(["netsh", "wlan", "show", "interfaces"]) or "").strip()
            if not raw:
                return False, "WLAN 服务没响应，请确认无线开关已打开"
            first = " / ".join(raw.splitlines()[:4])[:150]
            return False, "无线网卡状态解析失败。netsh 原始输出：%s" % first

        if cur != SSID or not is_connected(SSID):
            self.log("正在切换到 %s …" % SSID)
            connect_wifi(iface)
            if not wait_connected(15):
                return False, "连不上 %s，请确认信号正常" % SSID

        # 关联上不等于分到 IP。没有 IP 就发请求，只会撞一句
        # 「认证服务器无响应（WinError 10065）」，用户完全不知道该怎么办。
        ip = local_ip_toward()
        if not ip:
            self.log("已连上 %s，正在等分配 IP …" % SSID)
            ip = wait_ip(20)
        if not ip:
            return False, ("连上 %s 了，但一直没分到 IP 地址。\n"
                           "请断开 WiFi 再重连一次，然后重新点「直连」。"
                           % SSID)

        self.log("正在向门户认证…")
        ok, msg, data = try_login(account, password, ip)

        # 门户压根没回话（多半是刚连上、路由还没通）—— 等两秒再来一次。
        # 这一下能挡掉「第一次点失败、第二次就好」里剩下的那部分。
        if data is None and not ok:
            self.log("门户没应答，等两秒重试一次…")
            time.sleep(2)
            ok, msg, data = try_login(account, password, ip)

        # 门户先看 IP 再看账号：这个 IP 上还挂着会话时，它会回 clientip online，
        # 而且**根本不校验账号密码**，打什么账号都是这一句。不把旧会话清掉，
        # 换账号、换电脑、重装系统之后全都登不进去。
        #
        # 这里不再要求 force：能走到这一步，说明开头的联网检测已经确认
        # 「**上不了网**」了（真能上网早就 return 了）。所以门户记着的那个会话
        # 是个僵死的空壳，清掉它不会打断任何人。
        if not ok and is_client_online(data):
            self.log("旧账号还占着这个网络，先注销…")
            uid = self.last_uid or (account + "@telecom")
            done, dmsg = portal_logout(uid, ip, read_mac())
            if done:
                self.log("注销成功（%s），正在登入新账号…" % dmsg)
                # 门户那边拆会话有延迟，等 1.5/2.5/3.5 秒各试一次，
                # 免得偶尔赶不及，又回一个 clientip online
                for wait in (1.5, 2.5, 3.5):
                    time.sleep(wait)
                    ok, msg, data = try_login(account, password, ip)
                    if ok:
                        break
            else:
                self.log("注销没成功：%s" % dmsg)

        if not ok:
            # 兜底：页面会话参数可能过期，重取一次再试
            self.log("仍未通过，重取门户参数后重试…")
            dyn = refresh_dynamic()
            if dyn:
                ok, msg, data = try_login(account, password, ip, dynamic=dyn)

        # 还是不行。**只有门户明说是名额满了**，才去自助服务踢掉一台不是本机的
        # 再回来重登；第一次能直接进去的话根本走不到这里，也说明本来就沒满。
        # 判据见 should_try_free_slot —— 别再把 mac error / ip_exist 这种踢设备
        # 也治不了的失败也拉去跑一趟（那还会白踢掉用户另一台设备）。
        if not ok and not should_try_free_slot(data):
            log_line("这次不跑自助服务（%s）"
                     % describe_failure(data, "").splitlines()[0])

        if not ok and should_try_free_slot(data):
            freed, fmsg = self.try_free_a_slot(account, password)
            if freed:
                self.log(fmsg)
                self.log("名额腾出来了，重新认证…")
                # 门户那边名额释放也有一点延迟，多试几次
                for wait in (1.0, 2.0, 3.0):
                    time.sleep(wait)
                    ok, msg, data = try_login(account, password, ip)
                    if ok:
                        break
            else:
                log_line("没能腾出名额: %s" % fmsg)

        if not ok:
            return False, msg

        if data and data.get("uid"):
            self.last_uid = data["uid"]

        self.log("验证外网连通性…")
        online, why = wait_online()
        log_line("连通性探测: %s | %s" % (online, why))
        if not online:
            # 光记一句「不通」没法定位，把代理设置和 DNS 解析都写进日志
            for line in diagnose_network():
                log_line("诊断 " + line)
            return False, ("门户说认证成功，但外网探测不通（%s）。\n"
                           "多半是这台机器的网络还没放行，稍等十几秒再点一次\n"
                           "「直连」；要是还不行，请把 run.log 发我看看。" % why)
        return True, "连接成功"


# ------------------------------------------------------------------ 界面

class App:
    def __init__(self, already_online=False):
        self.cfg = load_config()
        self.busy = False
        self.btn = None          # 当前主按钮（已在线视图里没有）
        self.form_mode = False   # 当前窗口显示的是不是账号密码表单
        self.force = False       # 是否跳过「已在线」判断、强制认证一次
        self._pos = None         # 窗口左上角（首次定位后固定，免得状态变化时乱跳）

        self.root = tk.Tk()
        self.root.title("校园网直连")
        self.root.resizable(False, False)

        self.status = tk.StringVar(value="")
        self.acc_var = tk.StringVar(value=self.cfg["account"] if self.cfg else "")
        self.pwd_var = tk.StringVar(value=self.cfg["password"] if self.cfg else "")

        if already_online:
            # 已经联网还双击图标，只可能是想换账号或清理后台 —— 给这两个按钮就够
            self._build_online()
        elif self.cfg:
            self._build_quick()
            self.root.after(250, self.on_connect)
        else:
            self._build_form(
                head="首次使用，请输入校园网账号",
                hint="账号密码会用 Windows 系统加密后保存在本机，只用于登录校园网。",
                btn="直连并保存",
                force=False)
        self._center()

    # ---------- 布局

    def _center(self, w=340):
        """宽度固定，高度随内容自适应。左上角只在首次定位，之后固定不动。"""
        self.root.update_idletasks()
        h = self.root.winfo_reqheight()
        if self._pos is None:
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            self._pos = (max(0, (sw - w) // 2), max(0, (sh - h) // 3))
        x, y = self._pos
        self.root.geometry("%dx%d+%d+%d" % (w, h, x, y))

    def _set_status(self, msg):
        """改状态文字后重新量一次高度，免得长句子被窗口截掉。"""
        self.status.set(msg)
        self.root.after_idle(self._center)

    def _clear(self):
        for child in self.root.winfo_children():
            child.destroy()

    def _link(self, parent, text, cmd):
        """一行可点的小字。"""
        lab = ttk.Label(parent, text=text, foreground="#0a66c2", cursor="hand2")
        lab.bind("<Button-1>", lambda _e: cmd())
        return lab

    def _build_online(self):
        """已经联网：只给「切换账号」和「关闭后台」两个按钮，不摆表单出来。"""
        self.form_mode = False
        self.force = True
        f = ttk.Frame(self.root, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="校园网直连", font=("Microsoft YaHei UI", 12, "bold")
                  ).pack(pady=(0, 2))
        ttk.Label(f, text="当前已经联网 ✓", foreground="#2e7d32"
                  ).pack(pady=(0, 14))
        ttk.Button(f, text="切换账号", width=18,
                   command=self._to_form).pack(pady=4)
        ttk.Button(f, text="关闭后台", width=18,
                   command=self.on_kill_background).pack(pady=4)
        ttk.Label(f, textvariable=self.status, foreground="#555",
                  wraplength=290, justify="center").pack(pady=(10, 0))

    def _build_quick(self):
        """已有账号、但当前没在线 —— 只给一个「直连」按钮。"""
        self.form_mode = False
        self.force = False
        f = ttk.Frame(self.root, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="校园网直连", font=("Microsoft YaHei UI", 12, "bold")
                  ).pack(pady=(0, 12))
        self.btn = ttk.Button(f, text="直  连", width=18, command=self.on_connect)
        self.btn.pack(pady=4)
        ttk.Label(f, textvariable=self.status, foreground="#555",
                  wraplength=290, justify="center").pack(pady=(12, 0))
        row = ttk.Frame(f)
        row.pack(pady=(12, 0))
        self._link(row, "切换账号", self._to_form).pack(side="left")
        ttk.Label(row, text=" · ", foreground="#bbb").pack(side="left")
        self._link(row, "关闭后台", self.on_kill_background).pack(side="left")

    def _build_form(self, head, hint, btn, force):
        """账号密码表单：首次使用 / 已在线时切换账号，都用这个。"""
        self.form_mode = True
        self.force = force
        f = ttk.Frame(self.root, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text=head, font=("Microsoft YaHei UI", 10, "bold")
                  ).grid(row=0, column=0, columnspan=2, pady=(0, 12), sticky="w")
        ttk.Label(f, text="账号").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        e1 = ttk.Entry(f, textvariable=self.acc_var, width=22)
        e1.grid(row=1, column=1, pady=4)
        ttk.Label(f, text="密码").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
        e2 = ttk.Entry(f, textvariable=self.pwd_var, width=22, show="•")
        e2.grid(row=2, column=1, pady=4)
        e2.bind("<Return>", lambda _e: self.on_connect())
        self.btn = ttk.Button(f, text=btn, width=18, command=self.on_connect)
        self.btn.grid(row=3, column=0, columnspan=2, pady=(14, 4))
        ttk.Label(f, textvariable=self.status, foreground="#555",
                  wraplength=290, justify="center"
                  ).grid(row=4, column=0, columnspan=2, pady=(4, 0))
        ttk.Label(f, text=hint, foreground="#777", wraplength=290, justify="left"
                  ).grid(row=5, column=0, columnspan=2, pady=(8, 0), sticky="w")
        self._link(f, "关闭后台", self.on_kill_background).grid(
            row=6, column=0, columnspan=2, pady=(10, 0))
        # 账号密码框始终预填当前值（首次运行时为空，切换账号时为已保存的）
        e1.focus_set()

    def _to_form(self):
        """把窗口从「直连」换成账号密码表单。"""
        if self.busy:
            return
        self._clear()
        self._set_status("")
        self._build_form(
            head="切换账号",
            hint="改完点下面按钮，会用新账号重新认证一次。",
            btn="切换并连接",
            force=True)
        self._center()

    # ---------- 交互

    def on_connect(self):
        if self.busy:
            return
        acc = self.acc_var.get().strip()
        pwd = self.pwd_var.get().strip()
        if not acc or not pwd:
            messagebox.showwarning("缺少信息", "请先填写账号和密码。", parent=self.root)
            return

        self.busy = True
        if self.btn:
            self.btn.config(state="disabled")
        self._set_status("正在连接…")
        threading.Thread(target=self._work, args=(acc, pwd, self.force),
                         daemon=True).start()

    def on_kill_background(self):
        """结束本程序的所有实例 + 清掉临时残留，然后退出。"""
        if self.busy:
            return
        self.busy = True
        self._set_status("正在清理后台残留…")
        self.root.update()          # 先把这句话画出来，免得看起来像卡住
        killed = kill_other_instances()
        time.sleep(0.6)     # 等被结束的进程把临时目录的句柄放开
        swept = sweep_mei()
        if killed or swept:
            msg = "已结束 %d 个残留进程、清理 %d 处临时文件，正在退出…" % (killed, swept)
        else:
            msg = "没有发现残留，正在退出…"
        self._set_status(msg)
        self.root.update()
        self.root.after(900, self._quit)

    def _emit(self, s):
        """状态既显示到界面，也写进日志。"""
        log_line("· " + s)
        try:
            self.root.after(0, self._set_status, s)
        except Exception:
            pass

    def _work(self, acc, pwd, force):
        log_line("开始连接: account=%s force=%s uid=%s"
                 % (acc, force, (self.cfg or {}).get("uid")))
        flow = Flow(self._emit, uid=(self.cfg or {}).get("uid"))
        uid = None
        try:
            ok, msg = flow.run(acc, pwd, force=force)
            uid = flow.last_uid
        except Exception as e:
            ok, msg = False, "程序出错：%r" % e
        self.root.after(0, self._done, ok, msg, acc, pwd, uid)

    def _done(self, ok, msg, acc, pwd, uid=None):
        if ok:
            try:
                save_config(acc, pwd, uid)
            except Exception:
                pass
            self.cfg = {"account": acc, "password": pwd, "uid": uid}
            self._set_status(msg)
            self.root.after(400, self._quit)
            return
        self.busy = False
        if self.btn:
            self.btn.config(state="normal")
        self._set_status(msg)
        if self.form_mode:
            # 已经在表单里了，直接报错就行
            messagebox.showerror("连接失败", msg, parent=self.root)
        elif messagebox.askyesno(
                "连接失败", "%s\n\n要换个账号试试吗？" % msg, parent=self.root):
            self._to_form()

    def _quit(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        # 保证进程立刻结束，不在后台残留任何东西
        os._exit(0)

    def mainloop(self):
        self.root.mainloop()


def main():
    log_start()
    log_line("程序启动  argv=%r" % (sys.argv[1:],))
    # 系统代理是这类「门户通了但外网上不了」的头号嫌疑，开机就记一笔
    try:
        log_line("系统代理: %s（本程序一律直连，不走代理）"
                 % (urllib.request.getproxies() or "无"))
    except Exception:
        pass
    # 注意：已经在线时**不能**直接退出 —— 那样用户永远打不开窗口，也就换不了账号。
    # 改成弹账号表单让他切换，不改就直接关掉窗口。
    try:
        online = is_online(timeout=3)
    except Exception:
        online = False
    log_line("启动时是否已在线: %s（决定弹哪个界面）" % online)
    App(already_online=online).mainloop()


if __name__ == "__main__":
    main()
