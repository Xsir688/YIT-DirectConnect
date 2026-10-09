# -*- coding: utf-8 -*-
"""
打包脚本：把 src/yit_connect.py 打成单个 exe，并复制到桌面。

用法：python build.py
产物：dist\\校园网直连.exe  ->  复制到 桌面\\校园网直连.exe
"""
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src", "yit_connect.py")
DIST = os.path.join(ROOT, "dist")
EXE_NAME = "校园网直连"
DESKTOP = os.path.join(os.environ["USERPROFILE"], "Desktop")


def run(cmd, **kw):
    print("> " + " ".join(cmd))
    return subprocess.run(cmd, **kw)


def main():
    if not os.path.isfile(SRC):
        sys.exit("找不到源文件：%s" % SRC)

    # 1. 确保 PyInstaller 可用
    probe = run([sys.executable, "-c", "import PyInstaller"],
                capture_output=True)
    if probe.returncode != 0:
        print("未安装 PyInstaller，正在安装…")
        if run([sys.executable, "-m", "pip", "install", "pyinstaller"]).returncode != 0:
            sys.exit("PyInstaller 安装失败")

    # 2. 打包
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",           # 单文件
        "--windowed",          # 不弹控制台
        "--clean",
        "--noconfirm",
        "--name", EXE_NAME,
        "--distpath", DIST,
        "--workpath", os.path.join(ROOT, "build"),
        "--specpath", os.path.join(ROOT, "build"),
        SRC,
    ]
    if run(cmd, cwd=ROOT).returncode != 0:
        sys.exit("打包失败")

    exe = os.path.join(DIST, EXE_NAME + ".exe")
    if not os.path.isfile(exe):
        sys.exit("打包产物不存在：%s" % exe)

    # 3. 复制到桌面（先结束正在运行的实例，否则文件被占用会复制失败）
    if os.path.isdir(DESKTOP):
        subprocess.run(["taskkill", "/f", "/im", EXE_NAME + ".exe"],
                       capture_output=True)
        target = os.path.join(DESKTOP, EXE_NAME + ".exe")
        for attempt in range(3):
            try:
                shutil.copy2(exe, target)
                break
            except PermissionError:
                if attempt == 2:
                    sys.exit("桌面文件被占用，请手动关掉「%s」后重试" % EXE_NAME)
                time.sleep(1)
        print("\n已复制到桌面：%s" % target)

    size = os.path.getsize(exe) / 1024 / 1024
    print("产物：%s（%.1f MB）" % (exe, size))
    print("\n可以双击桌面图标试用了。")


if __name__ == "__main__":
    main()
