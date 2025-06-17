# Python コード診断ツール

Version: 1.10

このツールは、Pythonコードの静的解析とセキュリティチェックを行う総合的な診断ツールです。コーディングスタイル、セキュリティ脆弱性、危険なコードパターン、依存関係の問題などを自動的に検出し、詳細なレポートを生成します。

## 📝 更新履歴

### v1.10 (2025-06-17)
- 🔧 GitHub Actionsワークフローの改善
  - エラー処理の強化（continue-on-error対応）
  - レポート生成とアーティファクト保存の最適化
  - テスト実行の安定性向上
- 📊 HTMLレポート機能の強化
- 🛡️ セキュリティチェックの信頼性向上

## 🌟 主な機能

- ✅ コーディングスタイルチェック（PEP 8準拠）
- 🛡️ セキュリティ脆弱性の検出
- ⚠️ 危険なコードパターンの特定
- 📦 依存関係の問題チェック
- 📊 HTMLレポート出力
- 🔄 CIパイプライン統合

## 🔍 検出対象となる主な問題

### セキュリティリスク
- 危険な関数の使用（eval, exec など）
- SQLインジェクションの可能性
- 安全でないデシリアライゼーション
- ファイルシステムの危険な操作
- 脆弱な暗号化実装
- 環境変数関連の危険な操作
- 不適切なログ出力

### 機密情報
- パスワードや認証情報
- APIキーや各種トークン
- 証明書や秘密鍵情報
- データベース接続情報
- クラウド認証情報

### 設定関連
- セキュリティ設定の無効化
- デバッグモードの有効化
- 危険なホスト設定
- SSL/TLS関連の設定

## 🚀 使用方法

### 基本的な使用方法
```bash
python code_checker.py target.py
```

### HTMLレポート出力
```bash
python code_checker.py target.py --html ./reports
```

### CIモードでの実行
```bash
python code_checker.py target.py --ci --severity MEDIUM
```

### すべての機能を使用
```bash
python code_checker.py target.py --html ./reports --ci --severity MEDIUM
```

## 📋 コマンドラインオプション

| オプション | 説明 |
|------------|------|
| `file` | チェック対象のPythonファイル（必須） |
| `--html DIR` | HTMLレポートの出力ディレクトリ |
| `--ci` | CIモードで実行（終了コードで結果を返す） |
| `--severity {HIGH,MEDIUM,LOW}` | CIモードでの失敗とみなす重要度の閾値（デフォルト: MEDIUM） |

## 📊 レポート形式

### 標準出力
- コーディングスタイルの問題
- セキュリティ脆弱性
- 危険なコードパターン
- 依存関係の問題

### HTMLレポート
- 見やすい形式でのレポート表示
- 問題の重要度に応じた色分け
- 詳細な説明と行番号の表示
- レスポンシブデザイン対応

## 🔄 CIパイプライン統合

### GitHub Actionsでの使用例
```yaml
name: Code Security Check

on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.x'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      
      - name: Run security check
        run: |
          python code_checker.py target.py --ci --severity MEDIUM --html ./reports
      
      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: ./reports/*.html
```

## ⚙️ 必要要件

```
pylint>=2.8.0
bandit>=1.7.0
safety>=2.0.0
```

## 📝 注意事項

- このツールは自動検出可能な問題のみを表示します
- より確実なセキュリティ評価には、手動でのコードレビューも併せて実施してください
- 誤検出の可能性もあるため、検出された問題は実際のコンテキストで判断してください

## 🔧 カスタマイズ

- 独自の危険なパターンの追加が可能
- セキュリティチェックの重要度閾値の調整
- レポート形式のカスタマイズ

## 📈 今後の予定

- [ ] より多くのセキュリティパターンの追加
- [ ] パフォーマンスの最適化
- [ ] さらなるCI/CDツールとの統合
- [ ] カスタムルールの設定ファイル対応

## 🤝 コントリビューション

バグ報告や機能要望は、Issueを作成してください。プルリクエストも歓迎です。

## 📄 ライセンス

MITライセンスの下で公開されています。
