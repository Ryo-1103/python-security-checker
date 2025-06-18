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
        
        # 現在の日時を取得
        now = datetime.datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")
        
        # HTMLテンプレート
        html_template = f"""
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Pythonコード診断レポート</h1>
                <div class="summary">
                    <p>📅 診断実施日時: {now}</p>
                    <p>📁 対象ファイル: {results['file']}</p>
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
                        <div class="issue warning">
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
                            <div class="issue error">
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
                            <div class="issue {severity_class}">
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
                        <div class="issue error">
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
                    html_template += f"""
                        <div class="issue warning">
                            <p>📍 行 {pattern['line']}: {type_desc} ({pattern['name']})</p>
                            <p>説明: {pattern.get('description', '説明なし')}</p>
                        </div>
                    """
        
        # 注意事項を追加
        html_template += """
                <h2>📝 注意事項</h2>
                <div class="issue info">
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

class CodeChecker:
    """コードチェッカークラス"""
    def __init__(self, path: str):
        """初期化"""
        self.path = path
        self._results = None

    def check_coding_style(self) -> List[Dict[str, Any]]:
        """Pylintを使用してコーディングスタイルをチェック"""
        try:
            # pythonでpylintを実行
            result = subprocess.run(
                [sys.executable, '-m', 'pylint', '--output-format=json', self.path],
                capture_output=True,
                text=True,
                check=False
            )
            return json.loads(result.stdout) if result.stdout else []
        except Exception as e:
            return [{'line': 0, 'message': f'Pylint実行エラー: {str(e)}'}]

    def check_security(self) -> List[Dict[str, Any]]:
        """Banditを使用してセキュリティ脆弱性をチェック"""
        try:
            # Banditをサブプロセスとして実行
            result = subprocess.run(
                [sys.executable, '-m', 'bandit', '-f', 'json', self.path],
                capture_output=True,
                text=True,
                check=False
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
        """危険なパターンを独自にチェック"""
        dangerous_patterns = []
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
                            # 新規追加：デシリアライゼーション関連
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
                            'executemany': 'SQLインジェクションの可能性があります',
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
        
        # 出力ディレクトリが存在しない場合は作成
        os.makedirs(output_dir, exist_ok=True)
        
        # ファイル名を生成（日時とファイル名から）
        base_name = os.path.splitext(os.path.basename(self.path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"report_{base_name}_{timestamp}.html")
        
        # HTMLレポートを生成
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
        summary.append("## 🔍 Pythonコード診断結果")
        summary.append(f"### 📁 対象ファイル: {results['file']}\n")
        
        # 重要度別の問題数をカウント
        security_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in results['security_issues']:
            if isinstance(issue, dict) and 'severity' in issue:
                security_counts[issue['severity']] = security_counts.get(issue['severity'], 0) + 1
        
        summary.append("### 🚨 セキュリティ問題")
        summary.append(f"- 重大な問題: {security_counts['HIGH']}件")
        summary.append(f"- 警告: {security_counts['MEDIUM']}件")
        summary.append(f"- 軽度な問題: {security_counts['LOW']}件\n")
        
        # 危険なパターンの数をカウント
        pattern_counts = {}
        for pattern in results['dangerous_patterns']:
            if isinstance(pattern, dict) and 'type' in pattern:
                pattern_counts[pattern['type']] = pattern_counts.get(pattern['type'], 0) + 1
        
        summary.append("### ⚡ 危険なパターン")
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

def main():
    """メイン関数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Pythonコードの静的解析とセキュリティチェックを行います')
    parser.add_argument('file', help='チェック対象のPythonファイル')
    parser.add_argument('--html', help='HTMLレポートの出力ディレクトリ（指定しない場合は実行ディレクトリ）')
    parser.add_argument('--ci', action='store_true', help='CIモードで実行（終了コードで結果を返す）')
    parser.add_argument('--severity', choices=['HIGH', 'MEDIUM', 'LOW'], default='MEDIUM',
                    help='CIモードでの失敗とみなす重要度の閾値（デフォルト: MEDIUM）')
    
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"⚠️ エラー: ファイル '{args.file}' が見つかりません。")
        sys.exit(1)

    print("\n🔍 コードの診断を開始します...")
    checker = CodeChecker(args.file)
    
    # 通常のチェック実行
    results = checker.run_all_checks()
    
    # HTMLレポート出力
    if args.html is not None:
        try:
            report_path = checker.generate_html_report(args.html)
            print(f"\n📊 HTMLレポートを生成しました: {report_path}")
        except Exception as e:
            print(f"⚠️ HTMLレポートの生成中にエラーが発生しました: {str(e)}")
    
    # CIモードの場合
    if args.ci:
        checker.print_ci_summary()
        sys.exit(checker.get_ci_exit_code(args.severity))
    
    # 通常モードの場合は詳細な結果を表示
    print("\n📊 コード診断結果")
    print(f"📁 対象ファイル: {results['file']}\n")

    # コーディングスタイルの問題を表示
    if results['style_issues']:
        print("\n⚠️ コーディングスタイルの問題")
        print("   PEP 8やベストプラクティスからの逸脱が見つかりました：")
        for issue in results['style_issues']:
            if isinstance(issue, dict):
                msg = issue.get('message', '不明なエラー')
                # 英語メッセージを日本語に変換
                msg = msg.replace("missing module docstring", "モジュールのドキュメント文字列がありません")
                msg = msg.replace("missing function docstring", "関数のドキュメント文字列がありません")
                msg = msg.replace("missing class docstring", "クラスのドキュメント文字列がありません")
                msg = msg.replace("too many local variables", "ローカル変数が多すぎます")
                msg = msg.replace("line too long", "行が長すぎます")
                msg = msg.replace("trailing whitespace", "行末に余分な空白があります")
                msg = msg.replace("bad indentation", "インデントが不適切です")
                msg = msg.replace("wrong variable name format", "変数名の形式が不適切です")
                print(f"   📍 行 {issue.get('line', '不明')}: {msg}")
            else:
                print(f"   {str(issue)}")

    # セキュリティの問題を表示
    if results['security_issues']:
        print("\n🚨 セキュリティの問題")
        print("   以下のセキュリティリスクが検出されました：")
        for issue in results['security_issues']:
            if isinstance(issue, dict):
                if 'error' in issue:
                    print(f"   ❌ {issue['error']}")
                else:
                    severity = issue.get('severity', '不明')
                    line = issue.get('line_number', '不明')
                    text = issue.get('issue_text', '不明な問題')
                    # 深刻度を日本語に変換
                    severity_jp = {
                        'HIGH': '🔴 重大',
                        'MEDIUM': '🟡 警告',
                        'LOW': '🟢 軽度',
                        'UNKNOWN': '❓ 不明'
                    }.get(severity, severity)
                    print(f"   📍 行 {line}: {text}")
                    print(f"      重要度: {severity_jp}")

    # 依存関係の問題を表示
    if results['dependency_issues']:
        print("\n📦 依存関係の脆弱性")
        print("   使用しているパッケージの脆弱性チェック結果：")
        for issue in results['dependency_issues']:
            if 'error' in issue:
                print(f"   ❌ {issue['error']}")
            elif 'info' in issue:
                print(f"   ℹ️  {issue['info']}")
            else:
                vuln_info = issue.get('vulnerability', {})
                if isinstance(vuln_info, dict):
                    vuln_desc = vuln_info.get('description', '詳細不明')
                else:
                    vuln_desc = str(vuln_info)
                print(f"   - パッケージ: {issue.get('package', '不明')} ({issue.get('version', '不明')})")
                print(f"     問題点: {vuln_desc}")

    # 危険なパターンを表示
    if results['dangerous_patterns']:
        print("\n⚡ 危険なコードパターン")
        print("   以下の潜在的なリスクが見つかりました：")
        for pattern in results['dangerous_patterns']:
            if 'error' in pattern:
                print(f"   ❌ {pattern['error']}")
            else:
                type_desc = {
                    'dangerous_function': '危険な関数の使用',
                    'dangerous_method': '危険なメソッドの使用',
                    'sensitive_variable': '機密情報を含む変数名',
                    'dangerous_setting': '危険な設定',
                    'dangerous_string': '危険な文字列パターン'
                }.get(pattern['type'], pattern['type'])
                print(f"   📍 行 {pattern['line']}: {type_desc} ({pattern['name']})")
                if 'description' in pattern:
                    print(f"      説明: {pattern['description']}")

    print("\n📝 注意事項:")
    print("   • このチェックは自動検出可能な問題のみを表示しています")
    print("   • より確実なセキュリティ評価には、手動でのコードレビューも併せて実施してください")
    print("   • 誤検出の可能性もあるため、検出された問題は実際のコンテキストで判断してください")

    # HTMLレポートの生成
    output_dir = os.path.dirname(args.file)
    output_file = os.path.join(output_dir, "code_check_report.html")
    html_report = HTMLReportGenerator.generate_html_report(results, output_file)
    print(f"\n📄 HTMLレポートが生成されました: {html_report}")

    # CIパイプライン統合のためのサマリー出力
    ci_summary = CIIntegration.generate_ci_summary(results)
    print("\n📋 CIパイプライン用サマリー")
    print(ci_summary)

    # 終了コードの決定
    exit_code = CIIntegration.get_exit_code(results, severity_threshold='MEDIUM')
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
