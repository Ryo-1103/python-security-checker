def analyze(code, results):
    issues = []
    if 'ADD ' in code:
        issues.append({'line': 1, 'issue': 'ADD命令はCOPY推奨'})
    if 'latest' in code:
        issues.append({'line': 1, 'issue': 'latestタグの使用は非推奨'})
    if 'USER root' in code:
        issues.append({'line': 1, 'issue': 'rootユーザーでの実行は危険'})
    results['docker_issues'] = issues
