def analyze(code, results):
    issues = []
    if 'hostNetwork: true' in code:
        issues.append({'line': 1, 'issue': 'hostNetwork: trueは推奨されません'})
    if 'runAsRoot: true' in code:
        issues.append({'line': 1, 'issue': 'runAsRoot: trueは危険'})
    results['k8s_issues'] = issues
