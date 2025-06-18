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

# XSS脆弱性
from flask import render_template_string
html = '<div>' + input() + '</div>'  # 直接HTML生成
render_template_string(html)  # テンプレートインジェクション

# SQLインジェクション
import sqlite3
def sql_injection_example(user_input):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE name = "%s"' % user_input)  # 文字列連結
    cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')  # f-string
    cursor.execute('SELECT * FROM users WHERE id = ' + user_input)  # 連結
    cursor.executescript('DROP TABLE users;')

# ファイルアップロードの危険パターン
class DummyFile:
    def save(self, path):
        pass
file = DummyFile()
file.save('../../etc/passwd')  # パストラバーサル
file.save('file.txt')  # 拡張子検証なし

# 暗号化の危険パターン
import hashlib
hashlib.md5(b'data').hexdigest()  # MD5
hashlib.sha1(b'data').hexdigest()  # SHA1
from Crypto.Cipher import DES
DES.new(b'12345678')  # DES
import random
random.random()  # 暗号用途での乱数

# エラーハンドリング
import traceback
def error_handling_example():
    try:
        1/0
    except Exception:
        traceback.print_exc()  # 情報漏洩
    except:
        pass  # broad except

# セッション設定
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None
session = {'id': 'abc'}
session['id'] = 'newid'  # セッションID直接操作

# CORS設定
headers = {'Access-Control-Allow-Origin': '*'}
headers['Access-Control-Allow-Headers'] = '*'

# キャッシュ設定
cache_control = 'Cache-Control: public'
@cache_page
def cached_view():
    pass

# デシリアライズ
import pickle
pickle.loads(b'bad')
import yaml
yaml.load('!!python/object/apply:os.system ["ls"]', Loader=yaml.FullLoader)

# ログ出力
import logging
logging.debug('secret info')
logging.exception('error!')

# 非推奨API
import os
os.popen('ls')

# 環境変数
import os
env = os.environ.get('SECRET_KEY')

# 依存関係の古いバージョン（requirements.txtでテスト）

# 直接パス・危険な文字列
open('/tmp/evil', 'w')
path = '../../etc/shadow'

# クラウド認証情報
aws_key = 'AKIAIOSFODNN7EXAMPLE'

# デバッグコード
print('debug')
console_log = 'console.log("test")'

def main():
    pass
