"""
コードチェッカー

このスクリプトは、Pythonコードの静的解析とセキュリティチェックを行います。
以下の項目をチェックします：
- コーディングスタイル（PEP 8）
- セキュリティ脆弱性
- 危険なコードパターン
- 依存関係の問題
- アクセス制御とユーザー認証
- 依存関係とライブラリのバージョン
- 非推奨メソッドの使用
- ハードコードされた機密情報
- トークンとセッション管理

また、以下の機能を提供します：
- HTMLレポート出力
- CIパイプライン統合
"""
import os
import ast
import sys
import json
import datetime
import subprocess
import re
from typing import List, Dict, Any, Set
from pathlib import Path
from packaging import version
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import argparse
import glob
import requests

# セキュリティチェックパターン
ACCESS_CONTROL_PATTERNS = {
    'unsafe_permissions': [
        (r'chmod\s+777', '危険な権限設定が検出されました'),
        (r'all_users', '全ユーザーアクセスの設定が検出されました'),
        (r'public\s*=\s*True', '公開設定が有効になっています'),
    ],
    'auth_bypass': [
        (r'disable_auth', '認証が無効化されています'),
        (r'skip_authentication', '認証がスキップされています'),
        (r'bypass_security', 'セキュリティチェックがバイパスされています'),
    ],
    'role_validation': [
        (r'admin\s*=\s*True', '管理者権限がハードコードされています'),
        (r'is_superuser\s*=', '特権ユーザー設定が直接操作されています'),
    ]
}

DEPRECATED_METHODS = {
    'python': [
        (r'cgi\.escape', 'cgi.escapeは非推奨です。html.escapeを使用してください'),
        (r'os\.popen', 'os.popenは非推奨です。subprocessを使用してください'),
        (r'os\.tmpnam', 'os.tmpnamは非推奨です。tempfileを使用してください'),
        (r'sys\.exc_clear', 'sys.exc_clearは非推奨です'),
    ],
    'django': [
        (r'auth\.models\.User\.is_authenticated\(\)', 'is_authenticated()は非推奨です。is_authenticatedプロパティを使用してください'),
        (r'urlresolvers', 'urlresolversは非推奨です。django.urlsを使用してください'),
    ],
    'flask': [
        (r'flask\.ext\.', 'flask.extは非推奨です。直接インポートを使用してください'),
    ]
}

HARDCODED_VALUES = {
    'credentials': [
        (r'password\s*=\s*["\'][^"\']+["\']', 'パスワードがハードコードされています'),
        (r'secret\s*=\s*["\'][^"\']+["\']', 'シークレットキーがハードコードされています'),
        (r'api_key\s*=\s*["\'][^"\']+["\']', 'APIキーがハードコードされています'),
    ],
    'connection_strings': [
        (r'postgresql:\/\/[^@]+@', 'データベース接続文字列に認証情報が含まれています'),
        (r'mysql:\/\/[^@]+@', 'データベース接続文字列に認証情報が含まれています'),
        (r'mongodb:\/\/[^@]+@', 'データベース接続文字列に認証情報が含まれています'),
    ],
}

TOKEN_SECURITY = {
    'token_expiry': [
        (r'expires_in\s*=\s*[0-9]{5,}', '長すぎるトークン有効期限が設定されています'),
        (r'timedelta\(days=[0-9]{2,}\)', '長すぎるセッション期限が設定されています'),
    ],
    'insecure_session': [
        (r'SESSION_COOKIE_SECURE\s*=\s*False', 'セキュアでないセッションクッキーの設定が検出されました'),
        (r'SESSION_EXPIRE_AT_BROWSER_CLOSE\s*=\s*False', 'ブラウザ終了時のセッション終了が無効化されています'),
    ],
}

# XSS対策パターン
XSS_PATTERNS = {
    'unsafe_html': [
        (r'mark_safe\([^)]+\)', '安全でないHTMLマークアップが使用されています'),
        (r'safe\s*=\s*True', '安全でないHTMLエスケープが設定されています'),
        (r'html_safe\s*=\s*True', 'HTMLコンテンツが安全でない方法でマークされています'),
    ],
    'template_injection': [
        (r'render_template_string', 'テンプレート文字列の直接レンダリングは危険です'),
        (r'Template\([^)]+\).render', '動的テンプレートのレンダリングにユーザー入力が含まれる可能性があります'),
    ],
    'js_injection': [
        (r'innerHTML\s*=', 'innerHTMLの使用は安全ではありません'),
        (r'document\.write\(', 'document.writeの使用は安全ではありません'),
    ]
}

# SQLインジェクション対策パターン
SQL_INJECTION_PATTERNS = {
    'raw_queries': [
        (r'execute\([^)]*%[^)]*\)', '文字列フォーマットを使用したSQLクエリが検出されました'),
        (r'raw\([^)]+\)', '生のSQLクエリが使用されています'),
        (r'cursor\.execute\([^)]*\+[^)]*\)', '文字列連結を使用したSQLクエリが検出されました'),
    ],
    'orm_unsafe': [
        (r'extra\([^)]+\)', 'Django ORMのextraメソッドは安全でない可能性があります'),
        (r'raw\([^)]+\)', 'Django ORMのrawメソッドは安全でない可能性があります'),
    ]
}

# ファイルアップロード対策パターン
FILE_UPLOAD_PATTERNS = {
    'unsafe_extensions': [
        (r'\.allow_extensions\s*=\s*[\'"]\*[\'"]', '全ての拡張子が許可されています'),
        (r'\.save\([^)]*\)', 'ファイル名の検証が不足している可能性があります'),
    ],
    'path_traversal': [
        (r'\.\./', 'パストラバーサルの可能性があります'),
        (r'os\.path\.join\([^)]*\.\.[^)]*\)', 'パストラバーサルの可能性があります'),
    ]
}

# 暗号化セキュリティパターン
CRYPTO_PATTERNS = {
    'weak_crypto': [
        (r'MD5', 'MD5は安全ではありません'),
        (r'SHA1', 'SHA1は安全ではありません'),
        (r'DES', 'DESは安全ではありません'),
    ],
    'weak_random': [
        (r'random\.|randint|randrange', '暗号用途には random モジュールは使用しないでください'),
        (r'math\.random', '暗号用途には math.random は使用しないでください'),
    ],
    'static_salt': [
        (r'salt\s*=\s*["\'][^"\']+["\']', 'ハードコードされたソルトが使用されています'),
    ]
}

# エラーハンドリングパターン
ERROR_HANDLING_PATTERNS = {
    'info_disclosure': [
        (r'traceback\.print_exc\(\)', 'トレースバック情報が漏洩する可能性があります'),
        (r'print_exception\(\)', '例外情報が漏洩する可能性があります'),
    ],
    'broad_except': [
        (r'except\s*:', '全ての例外を捕捉することは危険です'),
        (r'except\s+Exception:', '全ての例外を捕捉することは危険です'),
    ]
}

# セッション設定パターン
SESSION_PATTERNS = {
    'insecure_settings': [
        (r'SESSION_COOKIE_HTTPONLY\s*=\s*False', 'HTTPOnlyフラグが無効化されています'),
        (r'SESSION_COOKIE_SAMESITE\s*=\s*None', 'SameSite属性が無効化されています'),
    ],
    'session_fixation': [
        (r'session\.id\s*=', 'セッションIDの直接操作が検出されました'),
        (r'sessionid\s*=', 'セッションIDの直接操作が検出されました'),
    ]
}

# CORSセキュリティパターン
CORS_PATTERNS = {
    'unsafe_cors': [
        (r'Access-Control-Allow-Origin\s*:\s*\*', '全オリジンを許可するCORS設定が検出されました'),
        (r'add_header\s*["\']Access-Control-Allow-Origin[\'"]\s*["\']\\*["\']', '全オリジンを許可するCORS設定が検出されました'),
    ],
    'unsafe_headers': [
        (r'Access-Control-Allow-Headers\s*:\s*\*', '全ヘッダーを許可するCORS設定が検出されました'),
        (r'Access-Control-Allow-Methods\s*:\s*\*', '全メソッドを許可するCORS設定が検出されました'),
    ]
}

# キャッシュセキュリティパターン
CACHE_PATTERNS = {
    'sensitive_caching': [
        (r'Cache-Control\s*:\s*public', '機密情報に対する公開キャッシュ設定が検出されました'),
        (r'@cache_page', '機密情報に対するページキャッシュが検出されました'),
    ],
    'cache_headers': [
        (r'no-store\s*:\s*false', 'キャッシュ制御が不適切です'),
        (r'private\s*:\s*false', 'プライベートキャッシュ設定が無効化されています'),
    ]
}

# 最小要求バージョン
MINIMUM_VERSIONS = {
    'django': '3.2',
    'flask': '2.0',
    'requests': '2.25.0',
    'sqlalchemy': '1.4',
    'cryptography': '3.4',
}

class HTMLReportGenerator:
    """HTMLレポート生成クラス"""
    
    @staticmethod
    def generate_html_report(results: Dict[str, Any], output_path: str) -> str:
        """チェック結果からHTMLレポートを生成"""
        import collections
        # 現在の日時を取得
        now = datetime.datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")
        # --- 法令・ガイドライン収集 ---
        compliance_counter = collections.Counter()
        def collect_compliance(issue):
            if isinstance(issue, dict):
                text = issue.get('message') or issue.get('issue_text') or issue.get('description') or ''
                # for law in get_compliance_info(text):
                #     compliance_counter[law] += 1
        for issue in results.get('style_issues', []):
            collect_compliance(issue)
        for issue in results.get('security_issues', []):
            collect_compliance(issue)
        for issue in results.get('dangerous_patterns', []):
            collect_compliance(issue)
        compliance_list = list(compliance_counter.keys())
        # HTMLテンプレート
        html_template = f"""
        <!DOCTYPE html>
        <html lang=\"ja\">
        <head>
            <meta charset=\"UTF-8\">
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
            <title>Pythonコード診断レポート</title>
            <style>
                body {{
                    font-family: 'メイリオ', 'Meiryo', sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                h1, h2 {{
                    color: #333;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                }}
                .issue {{
                    margin: 10px 0;
                    padding: 10px;
                    border-left: 4px solid;
                }}
                .error {{ border-color: #dc3545; background-color: #fff5f5; }}
                .warning {{ border-color: #ffc107; background-color: #fff9e6; }}
                .info {{ border-color: #17a2b8; background-color: #f0f9fc; }}
                .success {{ border-color: #28a745; background-color: #f0fff4; }}
                .summary {{
                    margin: 20px 0;
                    padding: 15px;
                    background-color: #e9ecef;
                    border-radius: 5px;
                }}
                .compliance-list {{
                    margin: 10px 0 20px 0;
                    padding: 10px;
                    background: #f8f9fa;
                    border-radius: 5px;
                }}
                .compliance-label {{
                    display: inline-block;
                    background: #007bff;
                    color: #fff;
                    border-radius: 3px;
                    padding: 2px 8px;
                    margin: 2px 4px 2px 0;
                    font-size: 0.95em;
                }}
            </style>
        </head>
        <body>
            <div class=\"container\">
                <h1>Pythonコード診断レポート</h1>
                <div class=\"summary\">
                    <p>📅 診断実施日時: {now}</p>
                    <p>📁 対象ファイル: {results['file']}</p>
                </div>
                <div class=\"compliance-list\">
                    <b>本診断で検出された法令・ガイドライン:</b><br>
                    {('該当なし' if not compliance_list else ''.join(f'<span class="compliance-label">{law}</span>' for law in compliance_list))}
                </div>
        """
        
        # スタイル違反の結果を追加
        if results['style_issues']:
            html_template += """
                <h2>⚠️ コーディングスタイルの問題</h2>
                <p>PEP 8やベストプラクティスからの逸脱が見つかりました：</p>
            """
            for issue in results['style_issues']:
                if isinstance(issue, dict):
                    msg = issue.get('message', '不明なエラー')
                    line = issue.get('line', '不明')
                    html_template += f"""
                        <div class=\"issue warning\">
                            <p>📍 行 {line}: {msg}</p>
                        </div>
                    """
        
        # セキュリティの問題を追加
        if results['security_issues']:
            html_template += """
                <h2>🚨 セキュリティの問題</h2>
                <p>以下のセキュリティリスクが検出されました：</p>
            """
            for issue in results['security_issues']:
                if isinstance(issue, dict):
                    if 'error' in issue:
                        html_template += f"""
                            <div class=\"issue error\">
                                <p>❌ {issue['error']}</p>
                            </div>
                        """
                    else:
                        severity = issue.get('severity', '不明')
                        line = issue.get('line_number', '不明')
                        text = issue.get('issue_text', '不明な問題')
                        severity_class = {
                            'HIGH': 'error',
                            'MEDIUM': 'warning',
                            'LOW': 'info',
                            'UNKNOWN': 'info'
                        }.get(severity, 'info')
                        html_template += f"""
                            <div class=\"issue {severity_class}\">
                                <p>📍 行 {line}: {text}</p>
                                <p>重要度: {severity}</p>
                            </div>
                        """
        
        # 危険なパターンを追加
        if results['dangerous_patterns']:
            html_template += """
                <h2>⚡ 危険なコードパターン</h2>
                <p>以下の潜在的なリスクが見つかりました：</p>
            """
            for pattern in results['dangerous_patterns']:
                if 'error' in pattern:
                    html_template += f"""
                        <div class=\"issue error\">
                            <p>❌ {pattern['error']}</p>
                        </div>
                    """
                else:
                    type_desc = {
                        'dangerous_function': '危険な関数の使用',
                        'dangerous_method': '危険なメソッドの使用',
                        'sensitive_variable': '機密情報を含む変数名',
                        'dangerous_setting': '危険な設定',
                        'dangerous_string': '危険な文字列パターン'
                    }.get(pattern['type'], pattern['type'])
                    desc = pattern.get('description', '説明なし')
                    html_template += f"""
                        <div class=\"issue warning\">
                            <p>📍 行 {pattern['line']}: {type_desc} ({pattern['name']})</p>
                            <p>説明: {desc}</p>
                        </div>
                    """
        
        # 注意事項を追加
        html_template += """
                <h2>📝 注意事項</h2>
                <div class=\"issue info\">
                    <ul>
                        <li>このチェックは自動検出可能な問題のみを表示しています</li>
                        <li>より確実なセキュリティ評価には、手動でのコードレビューも併せて実施してください</li>
                        <li>誤検出の可能性もあるため、検出された問題は実際のコンテキストで判断してください</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """
        
        # HTMLファイルを保存
        output_file = Path(output_path)
        output_file.write_text(html_template, encoding='utf-8')
        
        return output_file.absolute().__str__()

class PDFReportGenerator:
    @staticmethod
    def generate_pdf_report(results, output_file):
        c = canvas.Canvas(output_file, pagesize=A4)
        width, height = A4
        y = height - 40
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "Pythonコード診断レポート")
        y -= 30
        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"生成日時: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 30
        
        def draw_section(title):
            nonlocal y
            c.setFont("Helvetica-Bold", 12)
            c.drawString(40, y, title)
            y -= 20
            c.setFont("Helvetica", 10)

        # コーディングスタイル
        if results.get('style_issues'):
            draw_section("コーディングスタイルの問題")
            for issue in results['style_issues']:
                msg = issue.get('message', str(issue))
                line = issue.get('line', '不明')
                c.drawString(60, y, f"行{line}: {msg}")
                y -= 15
                if y < 60:
                    c.showPage(); y = height - 40
        # セキュリティ
        if results.get('security_issues'):
            draw_section("セキュリティの問題")
            for issue in results['security_issues']:
                if isinstance(issue, dict):
                    text = issue.get('issue_text', str(issue))
                    line = issue.get('line_number', '不明')
                    severity = issue.get('severity', '不明')
                    c.drawString(60, y, f"行{line}: {text} (重要度: {severity})")
                    y -= 15
                    if y < 60:
                        c.showPage(); y = height - 40
        # 依存関係
        if results.get('dependency_issues'):
            draw_section("依存関係の脆弱性")
            for issue in results['dependency_issues']:
                pkg = issue.get('package', '不明')
                ver = issue.get('version', '不明')
                vuln = issue.get('vulnerability', {})
                desc = vuln.get('description', '詳細不明') if isinstance(vuln, dict) else str(vuln)
                c.drawString(60, y, f"{pkg} ({ver}): {desc}")
                y -= 15
                if y < 60:
                    c.showPage(); y = height - 40
        # 危険なパターン
        if results.get('dangerous_patterns'):
            draw_section("危険なコードパターン")
            for pattern in results['dangerous_patterns']:
                type_ = pattern.get('type', '不明')
                name = pattern.get('name', '')
                line = pattern.get('line', '不明')
                desc = pattern.get('description', '')
                c.drawString(60, y, f"行{line}: {type_} {name} {desc}")
                y -= 15
                if y < 60:
                    c.showPage(); y = height - 40
        c.save()
        return output_file

class CodeChecker:
    """コードチェッカークラス"""
    def __init__(self, path: str):
        """初期化"""
        self.path = path
        self._results = None

    def check_coding_style(self) -> List[Dict[str, Any]]:
        """Pylintを使用してコーディングスタイルをチェック"""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pylint', '--output-format=json', self.path],
                capture_output=True,
                text=True,
                check=True  # 安全な呼び出し
            )
            return json.loads(result.stdout) if result.stdout else []
        except Exception as e:
            return [{'line': 0, 'message': f'Pylint実行エラー: {str(e)}'}]

    def check_security(self) -> List[Dict[str, Any]]:
        """Banditを使用してセキュリティ脆弱性をチェック"""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'bandit', '-f', 'json', self.path],
                capture_output=True,
                text=True,
                check=True  # 安全な呼び出し
            )
            if result.stdout:
                data = json.loads(result.stdout)
                return [
                    {
                        'line_number': r['line_number'],
                        'issue_text': r['issue_text'],
                        'severity': r['issue_severity'].upper()
                    }
                    for r in data.get('results', [])
                ]
            return []
        except Exception as e:
            return [{'error': f'セキュリティチェックエラー: {str(e)}'}]

    def check_dependencies(self) -> List[Dict[str, Any]]:
        """依存関係の脆弱性をチェック"""
        try:
            return [{
                'info': '依存関係チェックはコマンドラインツール `safety check` の使用を推奨します。\n'
                       'インストール方法: pip install safety\n'
                       '使用方法: safety check'
            }]
        except Exception as e:
            return [{'error': f'依存関係チェックエラー: {str(e)}'}]

    def check_dangerous_patterns(self) -> List[Dict[str, Any]]:
        """危険なパターンを独自にチェック（自身の定義は除外）"""
        dangerous_patterns = []
        # code_checker.py自身は除外
        if os.path.basename(self.path) == "code_checker.py":
            return []
        try:
            with open(self.path, 'r', encoding='utf-8') as file:
                tree = ast.parse(file.read())
            for node in ast.walk(tree):
                # 1. 危険な関数とメソッドのチェック
                if isinstance(node, ast.Call):
                    # 関数呼び出しの確認
                    if isinstance(node.func, ast.Name):
                        dangerous_functions = {
                            'eval': '任意のコードを実行する可能性があります',
                            'exec': '任意のコードを実行する可能性があります',
                            'input': '安全でない入力を受け付ける可能性があります',
                            'pickle.loads': '悪意のあるコードを実行する可能性があります',
                            'marshal.loads': '悪意のあるコードを実行する可能性があります',
                            'shelve.open': '安全でないファイルアクセスの可能性があります',
                            'subprocess.call': 'シェルインジェクションの可能性があります',
                            'os.system': 'シェルインジェクションの可能性があります',
                            'os.popen': 'シェルインジェクションの可能性があります',
                            'tempfile.mktemp': '安全でない一時ファイルの作成',
                            'random.random': '暗号用途に適さない乱数生成',
                            'yaml.load': '安全でないYAMLデシリアライゼーション',
                            # 新規追加：ファイルシステム関連
                            'os.chmod': '危険なファイルパーミッション変更',
                            'os.chown': '危険なファイル所有者変更',
                            'os.remove': '危険なファイル削除操作',
                            'shutil.rmtree': '危険な再帰的ディレクトリ削除',
                            # 新規追加：暗号化関連
                            'DES.new': '脆弱な暗号化アルゴリズム(DES)の使用',
                            'RC4.new': '脆弱な暗号化アルゴリズム(RC4)の使用',
                            'MD5.new': '脆弱なハッシュアルゴリズム(MD5)の使用',
                            'SHA1.new': '脆弱なハッシュアルゴリズム(SHA1)の使用',
                            # 新規追加：デシリアゼーション関連
                            'jsonpickle.decode': '安全でないJSONデシリアライゼーション',
                            'yaml.unsafe_load': '安全でないYAMLデシリアライゼーション',
                            'cPickle.loads': '安全でないPickleデシリアライゼーション',
                            # 新規追加：ログ出力関連
                            'print': '本番環境での不適切なログ出力',
                            'logging.debug': '機密情報のデバッグログ出力の可能性'
                        }
                        if node.func.id in dangerous_functions:
                            dangerous_patterns.append({
                                'type': 'dangerous_function',
                                'name': node.func.id,
                                'line': node.lineno,
                                'description': dangerous_functions[node.func.id]
                            })
                    
                    # メソッド呼び出しの確認
                    elif isinstance(node.func, ast.Attribute):
                        dangerous_methods = {
                            'execute': 'SQLインジェクションの可能性があります',
                            'executescript': 'SQLインジェクションの可能性があります',
                            'load': '安全でないデータ読み込みの可能性があります',
                            'loads': '安全でないデータ読み込みの可能性があります',
                            'read': '安全でないファイル読み込みの可能性があります',
                            'write': '安全でないファイル書き込みの可能性があります',
                            'set_cookie': 'セキュアフラグなしのクッキー設定の可能性があります',
                            'verify_request': 'CSRFチェックの無効化の可能性があります',
                            'trust_all_roots': 'SSL証明書検証の無効化',
                            # 新規追加：ファイル操作関連
                            'chmod': '危険なファイルパーミッション変更',
                            'chown': '危険なファイル所有者変更',
                            'symlink': '危険なシンボリックリンク作成',
                            'truncate': '危険なファイル切り詰め操作',
                            # 新規追加：暗号化関連
                            'decrypt': '暗号化データの復号操作',
                            'gen_key': '暗号化キーの生成操作',
                            'derive_key': '鍵導出関数の使用',
                            # 新規追加：ログ関連
                            'exception': '例外スタックトレースのログ出力',
                            'critical': '重要なエラーのログ出力'
                        }
                        if node.func.attr in dangerous_methods:
                            dangerous_patterns.append({
                                'type': 'dangerous_method',
                                'name': f'{node.func.value.id}.{node.func.attr}' if hasattr(node.func.value, 'id') else node.func.attr,
                                'line': node.lineno,
                                'description': dangerous_methods[node.func.attr]
                            })

                # 2. 機密情報を含む変数名チェック
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            sensitive_patterns = {
                                'password': 'パスワード情報',
                                'secret': '機密情報',
                                'key': '暗号化キー',
                                'token': 'アクセストークン',
                                'auth': '認証情報',
                                'credential': '認証情報',
                                'cert': '証明書情報',
                                'private': '秘密情報',
                                'api_key': 'APIキー',
                                'access_token': 'アクセストークン',
                                'ssh_key': 'SSH鍵',
                                'master_key': 'マスターキー',
                                # 新規追加：環境変数関連
                                'env': '環境変数情報',
                                'environment': '環境変数情報',
                                'config': '設定情報',
                                'setting': '設定情報',
                                # 新規追加：データベース関連
                                'db_password': 'データベースパスワード',
                                'connection_string': '接続文字列',
                                'jdbc_url': 'JDBC URL',
                                # 新規追加：クラウド関連
                                'aws_key': 'AWSキー',
                                'azure_secret': 'Azureシークレット',
                                'gcp_credential': 'GCPクレデンシャル'
                            }
                            for pattern, desc in sensitive_patterns.items():
                                if pattern in target.id.lower():
                                    dangerous_patterns.append({
                                        'type': 'sensitive_variable',
                                        'name': target.id,
                                        'line': node.lineno,
                                        'description': f'{desc}を含む変数名が使用されています'
                                    })

                # 3. 安全でない設定パターンのチェック
                if isinstance(node, ast.Assign):
                    dangerous_settings = {
                        'DEBUG': 'デバッグモードの有効化',
                        'ALLOWED_HOSTS': '全許可のホスト設定',
                        'VERIFY': 'SSL検証の無効化',
                        'CHECK_HOSTNAME': 'ホスト名チェックの無効化',
                        'SECURE_SSL_REDIRECT': 'SSL強制リダイレクトの無効化',
                        'SESSION_COOKIE_SECURE': 'セキュアクッキーフラグの無効化',
                        'CSRF_COOKIE_SECURE': 'CSRFクッキーのセキュア設定の無効化',
                        'X_FRAME_OPTIONS': 'クリックジャッキング保護の無効化',
                        # 新規追加：環境設定関連
                        'ENVIRONMENT': '環境設定の直接指定',
                        'PRODUCTION': '本番環境フラグの無効化',
                        'DISABLE_SECURITY': 'セキュリティ機能の無効化',
                        'ALLOW_UNSAFE': '安全でない操作の許可',
                        # 新規追加：ログ関連
                        'LOG_LEVEL': 'ログレベルの設定',
                        'LOG_TO_STDOUT': '標準出力へのログ出力',
                        'LOG_SENSITIVE_DATA': '機密データのログ出力許可',
                        # 新規追加：キャッシュ関連
                        'CACHE_DISABLE': 'キャッシュの無効化',
                        'MEMORY_CACHE': 'メモリキャッシュの設定'
                    }
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in dangerous_settings:
                            if isinstance(node.value, (ast.Constant, ast.Num, ast.NameConstant)):
                                if (isinstance(node.value.value, bool) and node.value.value is False) or \
                                   (isinstance(node.value.value, (int, float)) and node.value.value == 0) or \
                                   (isinstance(node.value.value, str) and node.value.value.lower() in ['false', '0', '*']):
                                    dangerous_patterns.append({
                                        'type': 'dangerous_setting',
                                        'name': target.id,
                                        'line': node.lineno,
                                        'description': f'セキュリティ上重要な設定が無効化されています：{dangerous_settings[target.id]}'
                                    })

                # 4. 危険な文字列パターンのチェック
                if isinstance(node, ast.Str) or (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    dangerous_strings = {
                        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP).*(?:FROM|INTO|TABLE)': 'SQLクエリ文字列',
                        r'<script.*?>': 'スクリプトタグ',
                        r'javascript:': 'JavaScriptプロトコル',
                        r'data:text/html': 'データURLスキーム',
                        r'__proto__': 'プロトタイプ汚染',
                        r'/.*/|/etc/|/var/': 'ディレクトリトラバーサル',
                        # 新規追加：ファイルパス関連
                        r'/tmp/|/dev/|/proc/': '危険なシステムディレクトリへのアクセス',
                        r'\.\./|\.\./\.\./': 'ディレクトリトラバーサル',
                        r'file:///|\\\\': 'ファイルプロトコルの使用',
                        # 新規追加：環境変数関連
                        r'%\w+%|\$\w+|\${.*?}': '環境変数の参照',
                        r'AWS_|AZURE_|GCP_': 'クラウド認証情報の参照',
                        # 新規追加：暗号化関連
                        r'BEGIN (RSA|DSA|EC) PRIVATE KEY': '秘密鍵情報',
                        r'-----BEGIN CERTIFICATE-----': '証明書情報',
                        # 新規追加：デバッグ関連
                        r'console\.(log|debug|info)': 'コンソールログ出力',
                        r'debugger|alert\(': 'デバッグコード'
                    }
                    value = node.s if isinstance(node, ast.Str) else node.value
                    for pattern, desc in dangerous_strings.items():
                        import re
                        if re.search(pattern, value, re.IGNORECASE):
                            dangerous_patterns.append({
                                'type': 'dangerous_string',
                                'name': value[:50] + '...' if len(value) > 50 else value,
                                'line': node.lineno,
                                'description': f'危険な{desc}が含まれています'
                            })
        
        except Exception as e:
            dangerous_patterns.append({'error': f'パターンチェックエラー: {str(e)}'})
        
        return dangerous_patterns

    def run_all_checks(self) -> Dict[str, Any]:
        """すべてのチェックを実行"""
        self._results = {
            'file': self.path,
            'style_issues': self.check_coding_style(),
            'security_issues': self.check_security(),
            'dependency_issues': self.check_dependencies(),
            'dangerous_patterns': self.check_dangerous_patterns()
        }
        return self._results

    def generate_html_report(self, output_dir: str = None) -> str:
        """HTMLレポートを生成
        
        Args:
            output_dir: 出力ディレクトリ（指定がない場合は実行ディレクトリ）
            
        Returns:
            str: 生成されたHTMLファイルの絶対パス
        """
        if self._results is None:
            self.run_all_checks()
        if output_dir is None:
            output_dir = os.getcwd()
        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(self.path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"report_{base_name}_{timestamp}.html")
        return HTMLReportGenerator.generate_html_report(self._results, output_file)

    def get_ci_exit_code(self, severity_threshold: str = 'MEDIUM') -> int:
        """CIパイプライン用の終了コードを取得
        
        Args:
            severity_threshold: 失敗とみなす重要度の閾値（'HIGH', 'MEDIUM', 'LOW'）
            
        Returns:
            int: 0（成功）または1（失敗）
        """
        if self._results is None:
            self.run_all_checks()
        
        return CIIntegration.get_exit_code(self._results, severity_threshold)

    def print_ci_summary(self) -> None:
        """CIパイプライン用のサマリーを出力"""
        if self._results is None:
            self.run_all_checks()
        
        print(CIIntegration.generate_ci_summary(self._results))

class CIIntegration:
    """CIパイプライン統合クラス"""
    
    @staticmethod
    def get_exit_code(results: Dict[str, Any], severity_threshold: str = 'MEDIUM') -> int:
        """
        チェック結果に基づいて終了コードを決定
        
        Args:
            results: チェック結果
            severity_threshold: 失敗とみなす重要度の閾値 ('HIGH', 'MEDIUM', 'LOW')
            
        Returns:
            int: 0（成功）または1（失敗）
        """
        severity_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        threshold_level = severity_levels.get(severity_threshold, 2)
        
        # セキュリティ問題のチェック
        for issue in results['security_issues']:
            if isinstance(issue, dict) and 'severity' in issue:
                issue_level = severity_levels.get(issue['severity'], 0)
                if issue_level >= threshold_level:
                    return 1
        
        # 危険なパターンのチェック
        dangerous_patterns = results['dangerous_patterns']
        if any(pattern.get('type') in ['dangerous_function', 'dangerous_method'] 
               for pattern in dangerous_patterns if isinstance(pattern, dict)):
            return 1
        
        return 0
    
    @staticmethod
    def generate_ci_summary(results: Dict[str, Any]) -> str:
        """CIパイプライン用のサマリーを生成"""
        summary = []
        summary.append("## Pythonコード診断結果")
        summary.append(f"### 対象ファイル: {results['file']}\n")
        
        # 重要度別の問題数をカウント
        security_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in results['security_issues']:
            if isinstance(issue, dict) and 'severity' in issue:
                security_counts[issue['severity']] = security_counts.get(issue['severity'], 0) + 1
        
        summary.append("### セキュリティ問題")
        summary.append(f"- 重大な問題: {security_counts['HIGH']}件")
        summary.append(f"- 警告: {security_counts['MEDIUM']}件")
        summary.append(f"- 軽度な問題: {security_counts['LOW']}件\n")
        
        # 危険なパターンの数をカウント
        pattern_counts = {}
        for pattern in results['dangerous_patterns']:
            if isinstance(pattern, dict) and 'type' in pattern:
                pattern_counts[pattern['type']] = pattern_counts.get(pattern['type'], 0) + 1
        
        summary.append("### 危険なパターン")
        for pattern_type, count in pattern_counts.items():
            type_desc = {
                'dangerous_function': '危険な関数',
                'dangerous_method': '危険なメソッド',
                'sensitive_variable': '機密情報を含む変数',
                'dangerous_setting': '危険な設定',
                'dangerous_string': '危険な文字列パターン'
            }.get(pattern_type, pattern_type)
            summary.append(f"- {type_desc}: {count}件")
        
        return "\n".join(summary)

class SecurityChecker:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.issues: List[Dict[str, str]] = []

    def check_access_control(self, content: str) -> None:
        """アクセス制御とユーザー認証のチェック"""
        for category, patterns in ACCESS_CONTROL_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'アクセス制御',
                        'message': message,
                        'file': self.file_path
                    })

    def check_deprecated_methods(self, content: str) -> None:
        """非推奨メソッドのチェック"""
        for category, patterns in DEPRECATED_METHODS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'MEDIUM',
                        'category': '非推奨メソッド',
                        'message': message,
                        'file': self.file_path
                    })

    def check_hardcoded_values(self, content: str) -> None:
        """ハードコードされた値のチェック"""
        for category, patterns in HARDCODED_VALUES.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'ハードコード',
                        'message': message,
                        'file': self.file_path
                    })

    def check_token_security(self, content: str) -> None:
        """トークンとセッション管理のチェック"""
        for category, patterns in TOKEN_SECURITY.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'トークン管理',
                        'message': message,
                        'file': self.file_path
                    })

    def check_dependencies(self, requirements_path: str) -> None:
        """依存関係のバージョンチェック"""
        if not os.path.exists(requirements_path):
            return

        with open(requirements_path, 'r') as f:
            requirements = f.readlines()

        for req in requirements:
            req = req.strip()
            if '==' in req:
                pkg_name, pkg_version = req.split('==')
                if pkg_name in MINIMUM_VERSIONS:
                    min_version = MINIMUM_VERSIONS[pkg_name]
                    if version.parse(pkg_version) < version.parse(min_version):
                        self.issues.append({
                            'severity': 'HIGH',
                            'category': '依存関係',
                            'message': f'{pkg_name}の使用バージョン({pkg_version})が古すぎます。{min_version}以上にアップグレードしてください。',
                            'file': requirements_path
                        })

    def check_xss_vulnerabilities(self, content: str) -> None:
        """XSS脆弱性のチェック"""
        for category, patterns in XSS_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'XSS対策',
                        'message': message,
                        'file': self.file_path
                    })

    def check_sql_injection(self, content: str) -> None:
        """SQLインジェクション脆弱性のチェック"""
        for category, patterns in SQL_INJECTION_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'CRITICAL',
                        'category': 'SQLインジェクション',
                        'message': message,
                        'file': self.file_path
                    })

    def check_file_uploads(self, content: str) -> None:
        """ファイルアップロード関連の脆弱性チェック"""
        for category, patterns in FILE_UPLOAD_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'ファイルアップロード',
                        'message': message,
                        'file': self.file_path
                    })

    def check_crypto_usage(self, content: str) -> None:
        """暗号化関連のセキュリティチェック"""
        for category, patterns in CRYPTO_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': '暗号化セキュリティ',
                        'message': message,
                        'file': self.file_path
                    })

    def check_error_handling(self, content: str) -> None:
        """エラーハンドリングのセキュリティチェック"""
        for category, patterns in ERROR_HANDLING_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'MEDIUM',
                        'category': 'エラーハンドリング',
                        'message': message,
                        'file': self.file_path
                    })

    def check_session_security(self, content: str) -> None:
        """セッション関連のセキュリティチェック"""
        for category, patterns in SESSION_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'セッションセキュリティ',
                        'message': message,
                        'file': self.file_path
                    })

    def check_cors_security(self, content: str) -> None:
        """CORS設定のセキュリティチェック"""
        for category, patterns in CORS_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'HIGH',
                        'category': 'CORS設定',
                        'message': message,
                        'file': self.file_path
                    })

    def check_cache_security(self, content: str) -> None:
        """キャッシュ関連のセキュリティチェック"""
        for category, patterns in CACHE_PATTERNS.items():
            for pattern, message in patterns:
                if re.search(pattern, content):
                    self.issues.append({
                        'severity': 'MEDIUM',
                        'category': 'キャッシュセキュリティ',
                        'message': message,
                        'file': self.file_path
                    })

    def run_security_checks(self) -> List[Dict[str, str]]:
        """すべてのセキュリティチェックを実行"""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 既存のチェック
        self.check_access_control(content)
        self.check_deprecated_methods(content)
        self.check_hardcoded_values(content)
        self.check_token_security(content)

        # 新規追加のチェック
        self.check_xss_vulnerabilities(content)
        self.check_sql_injection(content)
        self.check_file_uploads(content)
        self.check_crypto_usage(content)
        self.check_error_handling(content)
        self.check_session_security(content)
        self.check_cors_security(content)
        self.check_cache_security(content)
        
        requirements_path = os.path.join(os.path.dirname(self.file_path), 'requirements.txt')
        self.check_dependencies(requirements_path)

        return self.issues

def save_history(results, org_name, target_file):
    import json
    import os
    from datetime import datetime
    try:
        history_dir = os.path.join(os.path.dirname(target_file), 'history')
        os.makedirs(history_dir, exist_ok=True)
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = os.path.splitext(os.path.basename(target_file))[0]
        fname = f"{org_name}_{base}_{date_str}.json"
        path = os.path.join(history_dir, fname)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"診断履歴を保存しました: {path}")
    except Exception as e:
        print(f"履歴保存エラー: {e}")

# 自動修正パターン（例）
AUTO_FIX_PATTERNS = [
    # (検出パターン, 修正後のコード, 修正案説明)
    (r'eval\(([^)]+)\)', r'ast.literal_eval(\1)', 'eval()は危険です。ast.literal_eval()に置き換えました'),
    (r'os\.popen\(([^)]+)\)', r'subprocess.run(\1, shell=True)', 'os.popenは非推奨です。subprocess.run()に置き換えました'),
    (r'cgi\.escape', r'html.escape', 'cgi.escapeは非推奨です。html.escapeに置き換えました'),
]

def suggest_and_fix_code(source_code: str):
    """
    検出パターンに基づき修正案を提示し、修正版コードを返す
    """
    suggestions = []
    fixed_code = source_code
    for pattern, replacement, message in AUTO_FIX_PATTERNS:
        import re
        if re.search(pattern, fixed_code):
            suggestions.append(message)
            fixed_code = re.sub(pattern, replacement, fixed_code)
    return suggestions, fixed_code

BEST_PRACTICE_SNIPPETS = [
    # 入力値バリデーション
    (r'def\s+([a-zA-Z0-9_]+)\(',
     """
    # 入力値バリデーション例
    # if not isinstance(arg, (int, str)):
    #     raise ValueError('不正な入力値です')
    """,
     '関数定義に入力値バリデーション例を挿入'),
    # try-exceptによるエラーハンドリング
    (r'(^|\n)([ \t]*)def\s+([a-zA-Z0-9_]+)\(([^)]*)\):\n([ \t]*)',
     """
\2def \3(\4):
\5    try:
\5        # ...既存の処理...
\5        pass
\5    except Exception as e:
\5        print(f'エラー: {e}')
""",
     '関数にエラーハンドリング例を挿入'),
    # セッション設定例
    (r'(^|\n)app\s*=\s*Flask\(',
     """
# セッションセキュリティ設定例
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
""",
     'Flaskアプリにセッションセキュリティ設定例を挿入'),
    # XSS対策関数例
    (r'(^|\n)def\s+render_html\(',
     """
# XSS対策例
import html
# ...
# safe_html = html.escape(user_input)
""",
     'HTMLレンダリング関数にXSS対策例を挿入'),
]

def insert_best_practices(source_code: str):
    """
    ベストプラクティス例を自動挿入
    """
    import re
    inserted = []
    fixed_code = source_code
    for pattern, snippet, message in BEST_PRACTICE_SNIPPETS:
        if re.search(pattern, fixed_code, re.MULTILINE):
            # 既に挿入済みでなければ追加
            if snippet.strip() not in fixed_code:
                fixed_code = re.sub(pattern, lambda m: m.group(0) + '\n' + snippet.strip() + '\n', fixed_code, count=1, flags=re.MULTILINE)
                inserted.append(message)
    return inserted, fixed_code

def load_user(username):
    import json
    userfile = os.path.join(os.path.dirname(__file__), 'users.json')
    if not os.path.exists(userfile):
        return None
    with open(userfile, encoding='utf-8') as f:
        users = json.load(f)
    for u in users:
        if u['username'] == username:
            return u
    return None

def notify_slack(summary, config_path='notifier_config.json'):
    import json
    if not os.path.exists(config_path):
        print('notifier_config.jsonがありません')
        return
    with open(config_path, encoding='utf-8') as f:
        conf = json.load(f)
    url = conf.get('slack_webhook_url')
    if not url or url.startswith('https://hooks.slack.com/services/XXXXXXXXX'):
        print('Slack Webhook URLが未設定です')
        return
    payload = {"text": summary}
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            print('✅ Slack通知を送信しました')
        else:
            print(f'⚠️ Slack通知失敗: {resp.status_code}')
    except Exception as e:
        print(f'⚠️ Slack通知エラー: {e}')

def notify_services(summary, config_path='notifier_config.json'):
    import json
    import requests
    if not os.path.exists(config_path):
        print('notifier_config.jsonがありません')
        return
    with open(config_path, encoding='utf-8') as f:
        conf = json.load(f)
    services = conf.get('services', [])
    # Slack
    if 'slack' in services:
        url = conf.get('slack_webhook_url')
        if url:
            payload = {"text": summary}
            try:
                resp = requests.post(url, json=payload)
                print('Slack通知:', resp.status_code)
            except Exception as e:
                print('Slack通知エラー:', e)
    # Teams
    if 'teams' in services:
        url = conf.get('teams_webhook_url')
        if url:
            payload = {"text": summary}
            try:
                resp = requests.post(url, json=payload)
                print('Teams通知:', resp.status_code)
            except Exception as e:
                print('Teams通知エラー:', e)
    # Discord
    if 'discord' in services:
        url = conf.get('discord_webhook_url')
        if url:
            payload = {"content": summary}
            try:
                resp = requests.post(url, json=payload)
                print('Discord通知:', resp.status_code)
            except Exception as e:
                print('Discord通知エラー:', e)
    # Google Chat
    if 'googlechat' in services:
        url = conf.get('googlechat_webhook_url')
        if url:
            payload = {"text": summary}
            try:
                resp = requests.post(url, json=payload)
                print('Google Chat通知:', resp.status_code)
            except Exception as e:
                print('Google Chat通知エラー:', e)
# ...existing code...

def main():
    import os  # ←ここで明示的にimport
    parser = argparse.ArgumentParser(description="Pythonコード診断ツール")
    parser.add_argument('--file', required=True, help='診断対象のPythonファイル')
    parser.add_argument('--html', help='HTMLレポート出力先ディレクトリ')
    parser.add_argument('--ci', action='store_true', help='CIモードで実行')
    parser.add_argument('--severity', default='MEDIUM', help='CI失敗とみなす重要度')
    parser.add_argument('--fix', action='store_true', help='自動修正を適用し修正版ファイルを出力')
    parser.add_argument('--insert-best-practices', action='store_true', help='セキュリティベストプラクティス例を自動挿入')
    parser.add_argument('--org', help='組織名（履歴ファイル名に使用）', default='defaultorg')
    parser.add_argument('--multi', nargs='+', help='複数ファイル/ディレクトリを一括スキャン')
    parser.add_argument('--user', help='実行ユーザー名（users.jsonで管理）', default='guest')
    parser.add_argument('--notify', action='store_true', help='診断結果をSlack等に通知')
    parser.add_argument('--lang', default='python', help='診断対象の言語（python, javascript, java, go, terraform, cloudformation, docker, k8s など）')
    parser.add_argument('--compliance', nargs='*', help='法令・ガイドライン名で準拠チェック（例: --compliance OWASP PCI GDPR）')
    parser.add_argument('--update-cve-db', action='store_true', help='NVDからCVEデータベースを自動更新')
    parser.add_argument('--check-cve', action='store_true', help='requirements.txtとCVE DBを突き合わせて新脆弱性を通知')
    args = parser.parse_args()

    if args.update_cve_db:
        update_cve_database()
        sys.exit(0)
    if args.check_cve:
        req_path = os.path.join(os.path.dirname(args.file), 'requirements.txt')
        found = check_cve_for_requirements(req_path)
        notify_new_cves(found)
        sys.exit(0)

    if not os.path.exists(args.file):
        print(f"⚠️ エラー: ファイル '{args.file}' が見つかりません。")
        sys.exit(1)

    user = load_user(args.user)
    if not user:
        print(f"ユーザー {args.user} は登録されていません。users.jsonを確認してください。")
        sys.exit(1)
    print(f"実行ユーザー: {user['username']} (権限: {user['role']})")
    if user['role'] != 'admin' and (args.fix or args.insert_best_practices):
        print("⚠️ この操作は管理者のみ実行可能です")
        sys.exit(1)

    results_list = []
    if args.multi:
        all_results = []
        compliance_summary = set()
        for target in args.multi:
            if os.path.isfile(target):
                checker = CodeChecker(target)
                result = checker.run_all_checks()
                all_results.append(result)
                if args.html:
                    checker.generate_html_report(args.html)
                save_history(result, args.org, target)
            elif os.path.isdir(target):
                for root, _, files in os.walk(target):
                    for file in files:
                        if file.endswith('.py'):
                            file_path = os.path.join(root, file)
                            checker = CodeChecker(file_path)
                            result = checker.run_all_checks()
                            all_results.append(result)
                            if args.html:
                                checker.generate_html_report(args.html)
                            save_history(result, args.org, file_path)
        for result in all_results:
            print(CIIntegration.generate_ci_summary(result))
    else:
        # print("[DEBUG] main() else節突入")
        checker = CodeChecker(args.file)
        results = checker.run_all_checks()
        # print(f"[DEBUG] run_all_checks完了 type={type(results)} keys={list(results.keys()) if isinstance(results, dict) else 'N/A'}")
        html_path = None
        if args.html:
            html_path = checker.generate_html_report(args.html)
            print(CIIntegration.generate_ci_summary(results))
        if args.ci:
            print(CIIntegration.generate_ci_summary(results))
            sys.exit(checker.get_ci_exit_code(args.severity))
        # print(f"[DEBUG] save_history呼び出し: org={args.org}, file={args.file}")
        try:
            save_history(results, args.org, args.file)
            # print("[DEBUG] save_history正常終了")
        except Exception as e:
            print(f"履歴保存エラー: {e}")
        # 診断結果の詳細案内（自動ブラウザ起動は行わずパスのみ表示）
        if html_path:
            print(f"\n診断結果の詳細はこちらから確認ください: {html_path}")
        if args.notify:
            summary = CIIntegration.generate_ci_summary(results)
            notify_services(summary)

if __name__ == "__main__":
    main()
