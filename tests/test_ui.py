# -*- coding: utf-8 -*-
"""界面自检：已联网/未联网两条入口、切换账号链路、关闭后台的安全性。
运行时会短暂闪现窗口，属正常。"""
import os
import sys
import inspect
import threading
import tkinter as tk
import tkinter.ttk as ttk

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import yit_connect as Y  # noqa: E402

FAILED = []


def check(name, got, want):
    ok = got == want
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if not ok:
        print("   期望: %r" % (want,))
        print("   实际: %r" % (got,))
        FAILED.append(name)


def texts(widget, cls):
    """递归收集某一类控件的文字。"""
    out = []
    for c in widget.winfo_children():
        if isinstance(c, cls):
            out.append(c.cget("text"))
        out.extend(texts(c, cls))
    return out


def buttons(w):
    return texts(w, ttk.Button)


def labels(w):
    return texts(w, ttk.Label)


def app(online):
    a = Y.App(already_online=online)
    a.root.update()
    return a


# ---------------------------------------------------------------- 已联网
a = app(True)
check("已联网时不直接摆出表单", a.form_mode, False)
check("已联网时有「切换账号」按钮", "切换账号" in buttons(a.root), True)
check("已联网时有「关闭后台」按钮", "关闭后台" in buttons(a.root), True)
check("已联网时不显示直连按钮", "直  连" in buttons(a.root), False)
check("已联网时界面有联网提示",
      any("已经联网" in t for t in labels(a.root)), True)

a._to_form()
a.root.update()
check("点「切换账号」后才出现表单", a.form_mode, True)
check("表单按钮是「切换并连接」", a.btn.cget("text"), "切换并连接")
check("表单预填了账号", bool(a.acc_var.get()), True)
check("切换时强制认证", a.force, True)
a.root.destroy()

# ---------------------------------------------------------------- 未联网
a = app(False)
check("未联网时按钮是「直  连」", a.btn.cget("text"), "直  连")
check("未联网时不强制认证", a.force, False)
check("未联网时有「切换账号」入口", "切换账号" in labels(a.root), True)
check("未联网时有「关闭后台」入口", "关闭后台" in labels(a.root), True)
a._to_form()
a.root.update()
check("未联网也能切到表单", a.form_mode, True)
a.root.destroy()

# ---------------------------------------------------------------- 首次使用
Y_CFG = Y.CONFIG_FILE
Y.load_config()


def app_no_cfg(online):
    """临时把配置藏起来，模拟首次使用。"""
    real = Y.CONFIG_FILE
    Y.CONFIG_FILE = real + ".nonexistent"
    try:
        a = Y.App(already_online=online)
        a.root.update()
        return a
    finally:
        Y.CONFIG_FILE = real


a = app_no_cfg(False)
check("首次使用时直接给表单", a.form_mode, True)
check("首次使用按钮是「直连并保存」", a.btn.cget("text"), "直连并保存")
check("首次使用不强制认证", a.force, False)
a.root.destroy()

# ---------------------------------------------------------------- 窗口高度自适应
a = app(True)
h1 = a.root.winfo_height()
a._set_status("登录失败：" + "很长的错误信息用来测试换行" * 3)
a.root.update()
check("长状态文字时窗口自动变高", a.root.winfo_height() > h1, True)
a.root.destroy()

# ---------------------------------------------------------------- 关闭后台的安全性
check("从源码运行时不按名字杀进程（防误伤 python）",
      Y.self_exe_name(), None)
check("未打包时 kill_other_instances 不动手", Y.kill_other_instances(), 0)

# tasklist CSV 样例：两条本程序实例、一条别人的程序
SAMPLE = (
    '"校园网直连.exe","1111","Console","1","10,000 K"\n'
    '"校园网直连.exe","2222","Console","1","10,000 K"\n'
    '"chrome.exe","3333","Console","1","10,000 K"\n'
    "INFO: No tasks are running which match the specified criteria.\n"
)
EXE = "校园网直连.exe"
check("保护自己与引导父进程后，无可杀目标",
      Y.pick_pids_to_kill(SAMPLE, {1111, 2222}, EXE), [])
check("只保护自己时，父进程仍会被杀（防止临时目录残留）",
      Y.pick_pids_to_kill(SAMPLE, {1111}, EXE), [2222])
check("绝不把别的程序卷进来（按名字再核一遍）",
      Y.pick_pids_to_kill(SAMPLE, set(), EXE), [1111, 2222])
check("名字大小写不敏感",
      Y.pick_pids_to_kill(SAMPLE, set(), "校园网直连.EXE"), [1111, 2222])
check("关闭后台接口存在", callable(getattr(Y.App, "on_kill_background", None)), True)
check("Flow.run 接受 force 参数",
      "force" in inspect.signature(Y.Flow.run).parameters, True)

# ------------------------------------------------- 验证码那套已经删干净了
check("App 不再有验证码弹窗", hasattr(Y.App, "ask_captcha"), False)
check("Flow 不再收 ask_captcha",
      "ask_captcha" in inspect.signature(Y.Flow.__init__).parameters, False)
check("Flow 仍有 try_free_a_slot", callable(getattr(Y.Flow, "try_free_a_slot", None)), True)
check("自助服务能空跑验证码（登录的前提）",
      callable(getattr(Y.SelfService, "warm_up_captcha", None)), True)
check("不再依赖 tk 的 PNG 解码/线程投递逻辑",
      hasattr(Y.App, "_captcha_box"), False)

print()
print("失败项：%s" % (", ".join(FAILED) if FAILED else "无"))
sys.exit(1 if FAILED else 0)
