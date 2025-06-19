import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os
import json

class CodeCheckerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pythonコードセキュリティ診断ツール GUI")
        self.geometry("650x700")
        self.selected_file = ""
        self.selected_dir = ""
        self.custom_rules_path = os.path.join(os.path.dirname(__file__), 'custom_rules.json')
        self.users_path = os.path.join(os.path.dirname(__file__), 'users.json')
        self.settings_path = os.path.join(os.path.dirname(__file__), 'settings.json')
        self.users = self.load_users()
        self.settings = self.load_settings()
        self.notifier_conf = self.load_notifier_config()
        self.create_widgets()

    def load_users(self):
        try:
            with open(self.users_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def load_settings(self):
        try:
            with open(self.settings_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_settings(self):
        try:
            with open(self.settings_path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("設定保存エラー", str(e))

    def load_notifier_config(self):
        path = os.path.join(os.path.dirname(__file__), 'notifier_config.json')
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_notifier_config(self, conf):
        path = os.path.join(os.path.dirname(__file__), 'notifier_config.json')
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(conf, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("Slack設定保存エラー", str(e))

    def create_widgets(self):
        nb = ttk.Notebook(self)
        frm_main = ttk.Frame(nb)
        frm_settings = ttk.Frame(nb)
        nb.add(frm_main, text="診断・実行")
        nb.add(frm_settings, text="設定")
        nb.pack(fill="both", expand=True)
        # --- 診断・実行タブ ---
        # ファイル/ディレクトリ選択
        frm_select = ttk.LabelFrame(frm_main, text="診断対象の選択", padding=10)
        frm_select.pack(fill="x", padx=16, pady=10)
        self.file_var = tk.StringVar()
        self.dir_var = tk.StringVar()
        ttk.Label(frm_select, text="ファイル:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_select, textvariable=self.file_var, width=40, state="readonly").grid(row=0, column=1, padx=4)
        ttk.Button(frm_select, text="ファイル選択", command=self.select_file).grid(row=0, column=2, padx=4)
        ttk.Label(frm_select, text="または ディレクトリ:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm_select, textvariable=self.dir_var, width=40, state="readonly").grid(row=1, column=1, padx=4)
        ttk.Button(frm_select, text="ディレクトリ選択", command=self.select_dir).grid(row=1, column=2, padx=4)
        # ユーザー選択
        frm_user = ttk.LabelFrame(frm_main, text="実行ユーザー・通知先", padding=10)
        frm_user.pack(fill="x", padx=16, pady=10)
        self.user_var = tk.StringVar()
        user_names = [u['username'] for u in self.users] if self.users else ["admin"]
        ttk.Label(frm_user, text="ユーザー:").grid(row=0, column=0, sticky="w")
        self.cmb_user = ttk.Combobox(frm_user, textvariable=self.user_var, values=user_names, state="readonly", width=18)
        self.cmb_user.grid(row=0, column=1, padx=4, sticky="w")
        self.cmb_user.current(0)
        # Slack通知を有効化チェックボックスを削除
        # self.slack_notify_var = tk.BooleanVar(value=True)
        # ttk.Checkbutton(frm_user, text="Slack通知を有効化", variable=self.slack_notify_var).grid(row=0, column=2, padx=4, sticky="w")
        # オプション
        frm_opt = ttk.LabelFrame(frm_main, text="診断オプション", padding=10)
        frm_opt.pack(fill="x", padx=16, pady=10)
        self.html_var = tk.BooleanVar(value=True)
        self.ci_var = tk.BooleanVar()
        self.fix_var = tk.BooleanVar()
        self.best_var = tk.BooleanVar()
        self.notify_var = tk.BooleanVar()
        self.compliance_var = tk.StringVar()
        ttk.Checkbutton(frm_opt, text="HTMLレポート出力", variable=self.html_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(frm_opt, text="CIモード", variable=self.ci_var).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(frm_opt, text="自動修正", variable=self.fix_var).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(frm_opt, text="ベストプラクティス挿入", variable=self.best_var).grid(row=1, column=1, sticky="w")
        ttk.Checkbutton(frm_opt, text="通知（Slack等）", variable=self.notify_var).grid(row=2, column=0, sticky="w")
        ttk.Label(frm_opt, text="法令・ガイドライン(例: OWASP PCI GDPR)").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm_opt, textvariable=self.compliance_var, width=30).grid(row=3, column=1, padx=4, sticky="w")
        # カスタムルール編集
        frm_rule = ttk.LabelFrame(frm_main, text="カスタムルール", padding=10)
        frm_rule.pack(fill="x", padx=16, pady=10)
        ttk.Button(frm_rule, text="カスタムルールを編集", command=self.edit_custom_rules).pack(anchor="w")
        # 実行ボタン
        ttk.Button(frm_main, text="診断を実行", command=self.run_checker, style='Accent.TButton').pack(pady=18)
        # 出力欄
        self.txt_output = tk.Text(frm_main, height=8, font=('Meiryo', 10), bg="#f8f9fa")
        self.txt_output.pack(fill="both", padx=16, pady=4, expand=True)
        self.txt_output.insert("end", "ここに診断結果・進捗が表示されます\n")
        self.txt_output.config(state="disabled")
        # --- 設定タブ ---
        frm_set = ttk.LabelFrame(frm_settings, text="各種設定", padding=16)
        frm_set.pack(fill="x", padx=16, pady=16)
        self.var_check_style = tk.BooleanVar(value=self.settings.get("check_style", True))
        self.var_check_security = tk.BooleanVar(value=self.settings.get("check_security", True))
        self.var_check_dependency = tk.BooleanVar(value=self.settings.get("check_dependency", True))
        self.var_check_dangerous = tk.BooleanVar(value=self.settings.get("check_dangerous", True))
        self.var_use_custom_rules = tk.BooleanVar(value=self.settings.get("use_custom_rules", True))
        ttk.Checkbutton(frm_set, text="コーディングスタイルチェック", variable=self.var_check_style).pack(anchor="w")
        ttk.Checkbutton(frm_set, text="セキュリティ脆弱性チェック", variable=self.var_check_security).pack(anchor="w")
        ttk.Checkbutton(frm_set, text="依存関係チェック", variable=self.var_check_dependency).pack(anchor="w")
        ttk.Checkbutton(frm_set, text="危険パターンチェック", variable=self.var_check_dangerous).pack(anchor="w")
        ttk.Checkbutton(frm_set, text="カスタムルールを有効化", variable=self.var_use_custom_rules).pack(anchor="w")
        # 使用言語
        ttk.Label(frm_set, text="使用言語").pack(anchor="w", pady=(10,0))
        self.var_lang = tk.StringVar(value=self.settings.get("lang", "cpp"))
        lang_values = ["python", "javascript", "java", "go", "terraform", "cloudformation", "docker", "k8s", "cpp"]
        self.cmb_lang = ttk.Combobox(
            frm_set,
            textvariable=self.var_lang,
            values=lang_values,
            state="readonly",
            width=18
        )
        self.cmb_lang.pack(anchor="w")
        self.cmb_lang.bind("<<ComboboxSelected>>", lambda e: self.update_filetypes())
        # 通知サービス設定（1グループに集約）
        frm_notify = ttk.LabelFrame(frm_settings, text="通知サービス設定", padding=12)
        frm_notify.pack(fill="x", padx=16, pady=8)
        # サービス選択とWebhook欄
        self.var_notify_slack = tk.BooleanVar(value="slack" in self.notifier_conf.get("services", []))
        self.var_notify_teams = tk.BooleanVar(value="teams" in self.notifier_conf.get("services", []))
        self.var_notify_discord = tk.BooleanVar(value="discord" in self.notifier_conf.get("services", []))
        self.var_notify_googlechat = tk.BooleanVar(value="googlechat" in self.notifier_conf.get("services", []))
        self.var_slack_url = tk.StringVar(value=self.notifier_conf.get("slack_webhook_url", ""))
        self.var_teams_url = tk.StringVar(value=self.notifier_conf.get("teams_webhook_url", ""))
        self.var_discord_url = tk.StringVar(value=self.notifier_conf.get("discord_webhook_url", ""))
        self.var_googlechat_url = tk.StringVar(value=self.notifier_conf.get("googlechat_webhook_url", ""))
        self.var_slack_channel = tk.StringVar(value=self.notifier_conf.get("channel", ""))
        self.var_slack_user = tk.StringVar(value=self.notifier_conf.get("username", ""))
        self.var_slack_icon = tk.StringVar(value=self.notifier_conf.get("icon_emoji", ""))
        # 通知レベル（チェックボックス複数選択）
        notify_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        notify_on = set(self.notifier_conf.get("notify_on", ["HIGH","CRITICAL"]))
        self.var_notify_levels = {level: tk.BooleanVar(value=level in notify_on) for level in notify_levels}
        # サービス選択行
        ttk.Checkbutton(frm_notify, text="Slack", variable=self.var_notify_slack).grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_notify, textvariable=self.var_slack_url, width=35).grid(row=0, column=1, sticky="w")
        ttk.Label(frm_notify, text="チャンネル").grid(row=0, column=2, sticky="e")
        ttk.Entry(frm_notify, textvariable=self.var_slack_channel, width=10).grid(row=0, column=3, sticky="w")
        ttk.Label(frm_notify, text="Bot名").grid(row=0, column=4, sticky="e")
        ttk.Entry(frm_notify, textvariable=self.var_slack_user, width=10).grid(row=0, column=5, sticky="w")
        ttk.Label(frm_notify, text="アイコン").grid(row=0, column=6, sticky="e")
        ttk.Entry(frm_notify, textvariable=self.var_slack_icon, width=10).grid(row=0, column=7, sticky="w")
        ttk.Checkbutton(frm_notify, text="Teams", variable=self.var_notify_teams).grid(row=1, column=0, sticky="w")
        ttk.Entry(frm_notify, textvariable=self.var_teams_url, width=35).grid(row=1, column=1, columnspan=3, sticky="w")
        ttk.Checkbutton(frm_notify, text="Discord", variable=self.var_notify_discord).grid(row=2, column=0, sticky="w")
        ttk.Entry(frm_notify, textvariable=self.var_discord_url, width=35).grid(row=2, column=1, columnspan=3, sticky="w")
        ttk.Checkbutton(frm_notify, text="Google Chat", variable=self.var_notify_googlechat).grid(row=3, column=0, sticky="w")
        ttk.Entry(frm_notify, textvariable=self.var_googlechat_url, width=35).grid(row=3, column=1, columnspan=3, sticky="w")
        # 通知レベル行（Frameで横並びに美しく配置）
        ttk.Label(frm_notify, text="通知レベル").grid(row=4, column=0, sticky="w", pady=(8,0))
        frm_levels = ttk.Frame(frm_notify)
        frm_levels.grid(row=4, column=1, columnspan=7, sticky="w", pady=(8,0))
        for level in notify_levels:
            ttk.Checkbutton(frm_levels, text=level, variable=self.var_notify_levels[level]).pack(side="left", padx=8)

    def get_filetypes(self):
        lang = self.var_lang.get()
        ext_map = {
            "python": [("Pythonファイル", "*.py")],
            "javascript": [("JavaScriptファイル", "*.js")],
            "java": [("Javaファイル", "*.java")],
            "go": [("Goファイル", "*.go")],
            "terraform": [("Terraformファイル", "*.tf")],
            "cloudformation": [("YAMLファイル", "*.yaml"), ("YAMLファイル", "*.yml")],
            "docker": [("Dockerfile", "Dockerfile"), ("Dockerfile", "*.dockerfile")],
            "k8s": [("YAMLファイル", "*.yaml"), ("YAMLファイル", "*.yml")],
            "cpp": [("C++ファイル", "*.cpp"), ("C++ヘッダ", "*.hpp"), ("C++ファイル", "*.cc")],
        }
        return ext_map.get(lang, [("すべて", "*")]) + [("すべて", "*")]

    def update_filetypes(self):
        # ダイアログの拡張子フィルタを更新するためのダミー関数（必要に応じて拡張）
        pass

    def select_file(self):
        filetypes = self.get_filetypes()
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.file_var.set(path)
            self.dir_var.set("")

    def select_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.dir_var.set(path)
            self.file_var.set("")

    def edit_custom_rules(self):
        if not os.path.exists(self.custom_rules_path):
            with open(self.custom_rules_path, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)
        os.system(f'start notepad "{self.custom_rules_path}"')

    def run_checker(self):
        self.txt_output.config(state="normal")
        self.txt_output.delete("1.0", "end")
        self.txt_output.insert("end", "診断を開始します...\n")
        self.txt_output.config(state="disabled")
        self.update()
        # 仮想環境のpython.exeを明示的に使用
        python_cmd = os.path.join(os.path.dirname(__file__), '.venv', 'Scripts', 'python.exe')
        if not os.path.exists(python_cmd):
            python_cmd = 'python'  # fallback
        args = [python_cmd, "code_checker.py"]
        if self.file_var.get():
            args += ["--file", self.file_var.get()]
        elif self.dir_var.get():
            args += ["--multi", self.dir_var.get()]
        else:
            messagebox.showerror("エラー", "ファイルまたはディレクトリを選択してください")
            return
        if self.html_var.get():
            args += ["--html", os.path.join(os.path.dirname(__file__), "reports")]
        if self.ci_var.get():
            args.append("--ci")
        if self.fix_var.get():
            args.append("--fix")
        if self.best_var.get():
            args.append("--insert-best-practices")
        if self.notify_var.get():
            args.append("--notify")
        if self.compliance_var.get().strip():
            args += ["--compliance"] + self.compliance_var.get().strip().split()
        if self.user_var.get():
            args += ["--user", self.user_var.get()]
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="cp932",  # Windows日本語環境向け
                errors="replace",
                cwd=os.path.dirname(__file__)
            )
            for line in proc.stdout:
                self.txt_output.config(state="normal")
                self.txt_output.insert("end", line)
                self.txt_output.see("end")
                self.txt_output.config(state="disabled")
                self.update()
            proc.wait()
            self.txt_output.config(state="normal")
            self.txt_output.insert("end", f"\n診断が完了しました (終了コード: {proc.returncode})\n")
            self.txt_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("実行エラー", str(e))

    def on_save_settings(self):
        self.settings["check_style"] = self.var_check_style.get()
        self.settings["check_security"] = self.var_check_security.get()
        self.settings["check_dependency"] = self.var_check_dependency.get()
        self.settings["check_dangerous"] = self.var_check_dangerous.get()
        self.settings["use_custom_rules"] = self.var_use_custom_rules.get()
        self.settings["lang"] = self.var_lang.get()
        self.save_settings()
        # 通知サービス設定
        conf = self.notifier_conf
        services = []
        if self.var_notify_slack.get():
            services.append("slack")
        if self.var_notify_teams.get():
            services.append("teams")
        if self.var_notify_discord.get():
            services.append("discord")
        if self.var_notify_googlechat.get():
            services.append("googlechat")
        conf["services"] = services
        conf["slack_webhook_url"] = self.var_slack_url.get()
        conf["teams_webhook_url"] = self.var_teams_url.get()
        conf["discord_webhook_url"] = self.var_discord_url.get()
        conf["googlechat_webhook_url"] = self.var_googlechat_url.get()
        conf["channel"] = self.var_slack_channel.get()
        conf["username"] = self.var_slack_user.get()
        conf["icon_emoji"] = self.var_slack_icon.get()
        # 通知レベル（チェックボックス対応）
        conf["notify_on"] = [level for level, var in self.var_notify_levels.items() if var.get()]
        self.save_notifier_config(conf)
        messagebox.showinfo("保存完了", "設定を保存しました")

if __name__ == "__main__":
    app = CodeCheckerGUI()
    app.mainloop()
