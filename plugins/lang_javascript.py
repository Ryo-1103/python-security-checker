def analyze(code, results):
    import re
    issues = []
    # 例: evalの検出
    for m in re.finditer(r'eval\s*\(', code):
        issues.append({'line': code[:m.start()].count('\n')+1, 'issue': 'eval()の使用は危険です (JavaScript)'})
    # 例: document.writeの検出
    for m in re.finditer(r'document\.write\s*\(', code):
        issues.append({'line': code[:m.start()].count('\n')+1, 'issue': 'document.write()の使用は危険です'})
    results['js_issues'] = issues
