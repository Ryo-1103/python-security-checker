# 悪いコーディング例（テスト用）
import os
from typing import Any

# 危険な eval の使用
def dangerous_eval(code_str: str) -> Any:
    return eval(code_str)  # 危険！

# 機密情報を含む変数名
password = "secret123"  # 危険！
api_key = "my-secret-key"  # 危険！

# シェルコマンドインジェクションの可能性
def run_command(user_input: str) -> None:
    os.system(f"echo {user_input}")  # 危険！

# 安全でないファイル操作
def read_file(filename: str) -> str:
    with open(filename) as f:  # パスのバリデーションなし
        return f.read()

if __name__ == "__main__":
    # テストコード
    code = "2 + 2"
    result = dangerous_eval(code)
    print(f"Eval result: {result}")
    
    run_command("Hello World")
    
    try:
        content = read_file("test.txt")
        print(f"File content: {content}")
    except FileNotFoundError:
        print("File not found")
