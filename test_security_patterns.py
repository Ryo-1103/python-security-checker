"""セキュリティパターンのテストケース"""

# 危険なアクセス制御パターン
def unsafe_permission_example():
    import os
    os.chmod('file.txt', 777)  # 危険な権限設定
    all_users = True  # 全ユーザーアクセス
    settings = {'public': True}  # 公開設定

# 非推奨メソッドの使用
def deprecated_method_example():
    import cgi
    escaped = cgi.escape('<script>')  # 非推奨メソッド
    
    from django.core import urlresolvers  # 非推奨インポート
    
    if user.is_authenticated():  # 非推奨の呼び出し方
        pass

# ハードコードされた値
def hardcoded_values_example():
    password = "super_secret_password"  # ハードコードされたパスワード
    api_key = "1234567890abcdef"  # ハードコードされたAPIキー
    
    db_url = "postgresql://admin:password@localhost:5432/db"  # 認証情報を含むURL

# 危険なトークン設定
def token_security_example():
    token_config = {
        'expires_in': 31536000,  # 1年の有効期限
    }
    
    session_config = {
        'SESSION_COOKIE_SECURE': False,  # 安全でないセッション設定
        'SESSION_EXPIRE_AT_BROWSER_CLOSE': False,
    }
