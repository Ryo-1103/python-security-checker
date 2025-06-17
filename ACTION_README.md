# Python Security Checker Action

このGitHubアクションは、Pythonコードのセキュリティと品質を自動的にチェックします。

## 機能

- ✅ コーディングスタイルチェック（PEP 8準拠）
- 🛡️ セキュリティ脆弱性の検出
- ⚠️ 危険なコードパターンの特定
- 📦 依存関係の問題チェック
- 📊 HTMLレポート出力

## 使用方法

### 基本的な使用方法

```yaml
name: Security Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Python Security Check
        uses: your-username/python-security-checker@v1
        with:
          target: '.'
          severity: 'MEDIUM'
          html-output: 'reports'
          fail-on-severity: 'HIGH'
      
      - name: Upload security reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/
```

### 入力パラメータ

| パラメータ | 説明 | 必須 | デフォルト値 |
|------------|------|------|--------------|
| `target` | チェック対象のPythonファイルまたはディレクトリ | はい | `.` |
| `severity` | 問題検出の重要度閾値（HIGH/MEDIUM/LOW） | いいえ | `MEDIUM` |
| `html-output` | HTMLレポートの出力ディレクトリ | いいえ | `security-reports` |
| `fail-on-severity` | この重要度以上の問題が見つかった場合にCIを失敗させる | いいえ | `HIGH` |

### 特定のファイルのみをチェックする場合

```yaml
- name: Run Python Security Check
  uses: your-username/python-security-checker@v1
  with:
    target: './src/main.py'
    severity: 'HIGH'
```

### 特定のディレクトリをチェックする場合

```yaml
- name: Run Python Security Check
  uses: your-username/python-security-checker@v1
  with:
    target: './src'
    severity: 'MEDIUM'
```

## レポート

このアクションは2種類のレポートを生成します：

1. **コンソール出力**：
   - 見つかった問題の概要
   - 重要度別の問題数
   - エラーメッセージと該当箇所

2. **HTMLレポート**：
   - 詳細な分析結果
   - 問題の重要度に応じた色分け
   - ソースコードの該当箇所へのリンク
   - レスポンシブデザイン

## トラブルシューティング

### よくある問題と解決方法

1. **依存関係のエラー**：
   ```yaml
   - name: Install additional dependencies
     run: pip install -r requirements.txt
     # アクションの実行前に必要な依存関係をインストール
   ```

2. **特定のファイルを除外**：
   ```yaml
   - name: Run Python Security Check
     uses: your-username/python-security-checker@v1
     with:
       target: '.'
       exclude: 'tests/,examples/'
   ```

3. **CIの失敗を防ぐ**：
   ```yaml
   - name: Run Python Security Check
     continue-on-error: true  # チェックが失敗してもワークフローを続行
     uses: your-username/python-security-checker@v1
   ```

## ライセンス

このアクションはMITライセンスで提供されています。
