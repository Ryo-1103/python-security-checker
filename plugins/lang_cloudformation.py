def analyze(code, results):
    issues = []
    if '0.0.0.0/0' in code:
        issues.append({'line': 1, 'issue': '全開放CIDR(0.0.0.0/0)は危険'})
    if 'AccessKeyId' in code:
        issues.append({'line': 1, 'issue': 'AWSアクセスキーがハードコードされています'})
    results['cf_issues'] = issues
