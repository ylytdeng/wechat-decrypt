"""WeChat Decrypt GUI — 一键解密 / 导出消息 / 转换音频"""
import os
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

# 确保工作目录为脚本所在目录（打包后也适用）
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)


# ── 子任务入口（当以 --task 参数调用时直接执行对应脚本） ──────────────────────

# 显式导入：让 PyInstaller 收集子脚本需要的所有依赖
# （这些脚本通过 exec 动态加载，PyInstaller 无法自动检测）
import importlib.util  # noqa: F401 - used for dynamic loading
if False:  # noqa: never executed, only for PyInstaller dependency detection
    import sqlite3, hashlib, csv, json, re, glob, tempfile  # noqa: F401
    import xml.etree.ElementTree  # noqa: F401
    import functools, platform, ctypes, ctypes.wintypes  # noqa: F401
    import zstandard  # noqa: F401
    import pilk  # noqa: F401
    import Crypto, Crypto.Cipher, Crypto.Cipher.AES, Crypto.Util.Padding  # noqa: F401


def _run_subtask(task: str):
    """在子进程中被调用，直接执行对应脚本逻辑"""
    # 强制 stdout/stderr 为 UTF-8
    if sys.platform == "win32":
        for s in (sys.stdout, sys.stderr):
            if hasattr(s, "reconfigure"):
                s.reconfigure(encoding="utf-8", errors="replace")

    # onefile: _MEIPASS 临时目录; onedir: _internal/; 开发: BASE_DIR
    if getattr(sys, "frozen", False):
        script_dir = getattr(sys, "_MEIPASS", os.path.join(os.path.dirname(sys.executable), "_internal"))
    else:
        script_dir = BASE_DIR

    # 让 import 能找到脚本同目录的模块
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)

    mapping = {
        "decrypt": "main.py",
        "export": "export_messages.py",
        "voice": "voice_to_mp3.py",
    }
    script = mapping.get(task)
    if not script:
        print(f"未知任务: {task}", flush=True)
        sys.exit(1)

    script_path = os.path.join(script_dir, script)
    if not os.path.exists(script_path):
        # 开发模式回退到 BASE_DIR
        script_path = os.path.join(BASE_DIR, script)
    if not os.path.exists(script_path):
        print(f"脚本不存在: {script_path}", flush=True)
        sys.exit(1)

    # 将 decrypt 命令传给 main.py
    if task == "decrypt":
        sys.argv = ["main.py", "decrypt"]
    else:
        sys.argv = [script]

    # 设置环境变量，让 config.py 等脚本知道真正的应用目录
    os.environ["WECHAT_DECRYPT_APP_DIR"] = BASE_DIR
    os.chdir(BASE_DIR)

    # 加载并执行脚本
    spec = importlib.util.spec_from_file_location("__main__", script_path)
    mod = importlib.util.module_from_spec(spec)
    mod.__name__ = "__main__"
    spec.loader.exec_module(mod)


# ── 检查是否为子任务模式 ──────────────────────────────────────────────────────
if len(sys.argv) >= 3 and sys.argv[1] == "--task":
    _run_subtask(sys.argv[2])
    sys.exit(0)

# ── GUI 模式：隐藏控制台窗口 ────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WeChat Decrypt 工具箱")
        self.geometry("750x520")
        self.resizable(True, True)
        self.configure(bg="#f0f0f0")
        self._running = False

        self._build_ui()

    # ── UI 构建 ────────────────────────────────────────────────────────────
    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Big.TButton", font=("Microsoft YaHei UI", 11), padding=(16, 10))
        style.configure("TLabel", font=("Microsoft YaHei UI", 10), background="#f0f0f0")

        # 标题
        title = ttk.Label(self, text="WeChat Decrypt 工具箱", font=("Microsoft YaHei UI", 16, "bold"))
        title.pack(pady=(14, 6))

        # 按钮区域
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(4, 8))

        self.btn_decrypt = ttk.Button(
            btn_frame, text="① 解密数据库", style="Big.TButton",
            command=lambda: self._run_task("decrypt")
        )
        self.btn_decrypt.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_export = ttk.Button(
            btn_frame, text="② 导出消息", style="Big.TButton",
            command=lambda: self._run_task("export")
        )
        self.btn_export.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_voice = ttk.Button(
            btn_frame, text="③ 转换音频", style="Big.TButton",
            command=lambda: self._run_task("voice")
        )
        self.btn_voice.pack(side="left", expand=True, fill="x", padx=4)

        # 进度条
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=20, pady=(0, 4))

        # 日志区域
        log_label = ttk.Label(self, text="运行日志：")
        log_label.pack(anchor="w", padx=20)

        self.log = scrolledtext.ScrolledText(
            self, wrap="word", height=18,
            font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", state="disabled"
        )
        self.log.pack(fill="both", expand=True, padx=20, pady=(2, 10))

        # 底部状态
        self.status_var = tk.StringVar(value="就绪")
        status = ttk.Label(self, textvariable=self.status_var, font=("Microsoft YaHei UI", 9))
        status.pack(anchor="w", padx=20, pady=(0, 8))

    # ── 日志写入 ───────────────────────────────────────────────────────────
    def _log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ── 按钮状态 ───────────────────────────────────────────────────────────
    def _set_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.btn_decrypt.configure(state=state)
        self.btn_export.configure(state=state)
        self.btn_voice.configure(state=state)

    # ── 任务调度 ───────────────────────────────────────────────────────────
    def _run_task(self, task: str):
        if self._running:
            return
        self._running = True
        self._clear_log()
        self._set_buttons(False)
        self.progress.start(15)

        labels = {
            "decrypt": "解密数据库",
            "export": "导出消息记录",
            "voice": "转换音频文件",
        }
        self.status_var.set(f"正在{labels[task]}...")

        thread = threading.Thread(target=self._exec_task, args=(task,), daemon=True)
        thread.start()

    def _exec_task(self, task: str):
        try:
            cmd = [sys.executable, "--task", task]

            self._log(f">>> {' '.join(cmd)}\n\n")

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["WECHAT_DECRYPT_APP_DIR"] = BASE_DIR

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=BASE_DIR,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace")
                self.after(0, self._log, line)

            proc.wait()
            rc = proc.returncode
            if rc == 0:
                self.after(0, self._log, "\n✅ 完成！\n")
                self.after(0, self.status_var.set, "完成")
            else:
                self.after(0, self._log, f"\n❌ 进程退出，返回码: {rc}\n")
                self.after(0, self.status_var.set, f"失败 (返回码 {rc})")
        except Exception as e:
            self.after(0, self._log, f"\n❌ 异常: {e}\n")
            self.after(0, self.status_var.set, "异常")
        finally:
            self.after(0, self._on_task_done)

    def _on_task_done(self):
        self._running = False
        self.progress.stop()
        self._set_buttons(True)


if __name__ == "__main__":
    app = App()
    app.mainloop()
