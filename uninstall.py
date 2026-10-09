# -*- coding: utf-8 -*-
"""
一键卸载：把「校园网直连」在本机留下的所有东西清干净。

用法：
    python uninstall.py              交互式（默认，会先问一次）
    python uninstall.py --yes        不询问，直接删
    python uninstall.py --keep-src   只删运行痕迹，保留源码项目文件夹
    python uninstall.py --dry-run    只列出会删什么，不动手

会清掉：
  1. 正在运行的 校园网直连.exe 进程
  2. 桌面上的 校园网直连.exe
  3. %APPDATA%\\YITDirectConnect\\   （加密保存的账号密码）
  4. %TEMP% 下 PyInstaller 解压残留 _MEI*
  5. 本项目文件夹（含源码、构建产物）
  6. 检查并报告注册表自启动 / 计划任务（本程序从未写过，仅做确认）
"""
import os
import sys
import glob
import shutil
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
EXE_NAME = "校园网直连.exe"
APP_NAME = "YITDirectConnect"

APPDATA_DIR = os.path.join(os.environ.get("APPDATA", ""), APP_NAME)
DESKTOP_EXE = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop", EXE_NAME)
TEMP_DIR = os.environ.get("TEMP") or os.environ.get("LOCALAPPDATA", "")

ARGS = set(a.lower() for a in sys.argv[1:])
DRY = "--dry-run" in ARGS
ASSUME_YES = "--yes" in ARGS
KEEP_SRC = "--keep-src" in ARGS

removed, failed, skipped = [], [], []


def say(msg=""):
    print(msg)


def decode_console(raw: bytes) -> str:
    """系统命令输出编码因机器而异（UTF-8 或 GBK），先试 UTF-8。"""
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def kill_running():
    """结束正在运行的 exe。"""
    try:
        p = subprocess.run(["tasklist", "/fi", "imagename eq " + EXE_NAME],
                           capture_output=True, timeout=20)
        listing = decode_console(p.stdout or b"")
    except Exception:
        listing = ""
    if EXE_NAME.lower() not in listing.lower():
        return
    if DRY:
        say("  [dry] 结束进程 %s" % EXE_NAME)
        return
    say("  结束正在运行的进程…")
    subprocess.run(["taskkill", "/f", "/im", EXE_NAME],
                   capture_output=True, timeout=20)


def rm_path(path, label):
    if not os.path.exists(path):
        return
    if DRY:
        say("  [dry] 删除 %s  (%s)" % (path, label))
        return
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        removed.append("%s  (%s)" % (path, label))
        say("  已删除 %s" % path)
    except Exception as e:
        failed.append("%s -> %r" % (path, e))
        say("  !! 删除失败 %s -> %r" % (path, e))


def sweep_mei():
    """清掉 PyInstaller 在临时目录里的解压残留。"""
    if not TEMP_DIR or not os.path.isdir(TEMP_DIR):
        return
    for d in glob.glob(os.path.join(TEMP_DIR, "_MEI*")):
        rm_path(d, "PyInstaller 临时残留")


def check_registry():
    """确认没有自启动项（本程序从未写过，这里只是核实）。"""
    try:
        import winreg
    except Exception:
        return
    hits = []
    for hive, path in (
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ):
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                if APP_NAME.lower() in str(name).lower() or \
                   APP_NAME.lower() in str(val).lower() or \
                   EXE_NAME.lower() in str(val).lower():
                    hits.append("%s = %s" % (name, val))
                i += 1
            winreg.CloseKey(key)
        except Exception:
            continue
    if hits:
        say("  !! 发现自启动项（需要手动删）：")
        for h in hits:
            say("     " + h)
    else:
        say("  注册表自启动项：无（符合预期）")


def check_tasks():
    try:
        p = subprocess.run(["schtasks", "/query", "/fo", "csv"],
                           capture_output=True, timeout=30)
        out = decode_console(p.stdout or b"")
    except Exception:
        return
    hits = [ln for ln in out.splitlines()
            if APP_NAME.lower() in ln.lower() or EXE_NAME.lower() in ln.lower()]
    say("  计划任务：%s" % ("发现 %d 条（需要手动删）" % len(hits) if hits
                          else "无（符合预期）"))


def uninstall_pyinstaller():
    """PyInstaller 是本次为了打包才装的，问一下要不要一起卸掉。"""
    try:
        if subprocess.run([sys.executable, "-c", "import PyInstaller"],
                          capture_output=True).returncode != 0:
            say("  PyInstaller：未安装，跳过")
            return
    except Exception:
        return
    say("  PyInstaller：已安装（本次打包时装的）")
    if DRY:
        say("  [dry] 卸载 PyInstaller")
        return
    ans = "y" if ASSUME_YES else input("     要一并卸载 PyInstaller 吗？"
                                       "（其他项目可能用到）[y/N] ").strip().lower()
    if ans == "y":
        if subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y",
                           "pyinstaller"]).returncode == 0:
            say("     已卸载 pyinstaller")
        else:
            say("     !! 卸载失败，可手动执行："
                "python -m pip uninstall pyinstaller")
    else:
        skipped.append("PyInstaller（按你的选择保留）")


def self_delete_project():
    """项目文件夹里有本脚本自己，交给一个分离的 cmd 延迟删除。"""
    if KEEP_SRC or DRY:
        return
    say("\n  项目文件夹将在本窗口关闭后自动删除：%s" % ROOT)
    try:
        subprocess.Popen(
            'cmd /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "%s"' % ROOT,
            shell=True,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    except Exception as e:
        failed.append("项目文件夹 -> %r" % e)
        say("  !! 自动删除失败，请手动删掉 %s" % ROOT)


def main():
    say("=" * 60)
    say(" 校园网直连 —— 卸载程序" + ("（演练模式，不会真删）" if DRY else ""))
    say("=" * 60)
    say()

    if not DRY:
        say("将要清理：")
        say("  · 进程      %s" % EXE_NAME)
        say("  · 桌面      %s" % DESKTOP_EXE)
        say("  · 配置      %s" % APPDATA_DIR)
        say("  · 临时残留  %s\\_MEI*" % TEMP_DIR)
        if not KEEP_SRC:
            say("  · 项目      %s" % ROOT)
        say()
        if not ASSUME_YES:
            if input("确认卸载？[y/N] ").strip().lower() != "y":
                say("已取消，什么都没动。")
                return

    say("\n[1] 结束进程")
    kill_running()

    say("\n[2] 删除文件")
    rm_path(DESKTOP_EXE, "桌面程序")
    rm_path(APPDATA_DIR, "加密保存的账号密码")
    sweep_mei()
    if not KEEP_SRC:
        rm_path(os.path.join(ROOT, "dist"), "打包产物")
        rm_path(os.path.join(ROOT, "build"), "构建缓存")
        rm_path(os.path.join(ROOT, "__pycache__"), "缓存")
        rm_path(os.path.join(ROOT, "src", "__pycache__"), "缓存")
        rm_path(os.path.join(ROOT, "tests", "__pycache__"), "缓存")

    say("\n[3] 检查系统残留")
    check_registry()
    check_tasks()

    say("\n[4] Python 包")
    uninstall_pyinstaller()

    say("\n" + "=" * 60)
    say(" 已删除 %d 项" % len(removed))
    if skipped:
        say(" 按你要求保留：%s" % "；".join(skipped))
    if failed:
        say(" 以下没能删掉，需要手动处理：")
        for f in failed:
            say("   " + f)
    else:
        say(" 没有残留。")
    say("=" * 60)

    self_delete_project()

    if not DRY:
        try:
            input("\n按回车关闭…")
        except Exception:
            pass


if __name__ == "__main__":
    main()
