"""
C++用セキュリティプラグイン
このプラグインはC++コードの簡易的なセキュリティチェックを行います。
"""
import re

def check_cpp_security(file_path):
    issues = []
    with open(file_path, encoding='utf-8', errors='ignore') as f:
        code = f.read()
    # 危険な関数の使用チェック
    dangerous_functions = [
        'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'sscanf', 'vsprintf', 'system', 'popen', 'tmpnam', 'tmpfile'
    ]
    for func in dangerous_functions:
        pattern = rf'\b{func}\s*\('
        for m in re.finditer(pattern, code):
            issues.append({
                'line': code[:m.start()].count('\n') + 1,
                'message': f'危険な関数 {func} の使用を検出しました'
            })
    # ハードコードされたパスワードやキーの検出
    if re.search(r'password\s*=\s*"[^"]+"', code):
        issues.append({'message': 'ハードコードされたパスワードを検出'})
    if re.search(r'api_key\s*=\s*"[^"]+"', code):
        issues.append({'message': 'ハードコードされたAPIキーを検出'})
    return issues

def is_cpp_file(file_path):
    return file_path.endswith('.cpp') or file_path.endswith('.hpp') or file_path.endswith('.cc')
