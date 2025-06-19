# Python コード診断ツール

Version: 1.21

このツールは、Pythonコードの静的解析とセキュリティチェックを行う総合的な診断ツールです。コーディングスタイル、セキュリティ脆弱性、危険なコードパターン、依存関係の問題などを自動的に検出し、詳細なレポートを生成します。

## 📝 更新履歴

### 1.21 (2025-06-18)
- 🛠️ CI/CD安定化・自動リリース運用強化
  - PRコメント自動投稿の分岐（pull_request以外でのエラー回避）
  - Artifact（security-reports）未生成時のエラー回避（continue-on-error追加/ダミーファイル出力）
  - GitHub Actionsワークフローの現状に合わせた修正
  - READMEの全面刷新
- 📝 使用方法・CI/CD例・アーティファクト名の最新化
- 🐛 その他細かなバグ修正

### 1.20 (2025-06-18)
- 🔄 自動バージョン発番・リリース自動化
- 📝 コード・レポート出力の安定化

### 1.14 (2025-06-18)
- 🔍 以下の新しいセキュリティチェック項目を追加：
  - デシリアライゼーション攻撃対策
  - メモリ関連の脆弱性検出
  - DoS攻撃対策
  - APIセキュリティ
  - データ検証
  - ロギングとモニタリング
  - クラウドセキュリティ
  - コンテナセキュリティ
  - 依存関係の管理強化
  - セッション管理のセキュリティ

## 🌟 主な機能

- ✅ コーディングスタイルチェック（PEP 8準拠）
- 🛡️ セキュリティ脆弱性の検出
- ⚠️ 危険なコードパターンの特定
- 📦 依存関係の問題チェック
- 📊 HTMLレポート出力
- 🔄 CIパイプライン統合
- 🤖 PRコメント自動投稿（GitHub Actions）
- 📤 Slack/Discord/Teams/Google Chat通知

## 🚀 使用方法

### 基本的な使い方
```bash
python code_checker.py --file target.py
```

### HTMLレポート出力
```bash
python code_checker.py --file target.py --html ./reports
```

### CIモードでの実行
```bash
python code_checker.py --file target.py --ci --severity MEDIUM
```

### すべての機能を使用
```bash
python code_checker.py --file target.py --html ./reports --ci --severity MEDIUM --notify
```

### 複数ファイル/ディレクトリ一括スキャン
```bash
python code_checker.py --multi src/ tests/ --html ./reports
```

### 脆弱性DB連携・CVEチェック
```bash
python code_checker.py 任意のファイル.py --update-cve-db
python code_checker.py 任意のファイル.py --check-cve
```

## 📋 コマンドラインオプション

| オプション | 説明 |
|------------|------|
| `--file` | チェック対象のPythonファイル（必須） |
| `--multi DIR...` | 複数ファイル/ディレクトリ一括スキャン |
| `--html DIR` | HTMLレポートの出力ディレクトリ |
| `--ci` | CIモードで実行（終了コードで結果を返す） |
| `--severity {HIGH,MEDIUM,LOW}` | CIモードでの失敗とみなす重要度の閾値（デフォルト: MEDIUM） |
| `--notify` | Slack等に診断結果を通知 |
| `--user USERNAME` | 実行ユーザー指定（users.jsonで管理） |
| `--update-cve-db` | NVDからCVEデータベースを自動更新 |
| `--check-cve` | requirements.txtとCVE DBを突き合わせて新脆弱性を通知 |

## 📊 レポート形式

- 標準出力：コーディングスタイル・セキュリティ脆弱性・危険なコードパターン・依存関係の問題
- HTMLレポート：見やすい形式でのレポート表示（重要度色分け・詳細説明・行番号・レスポンシブ対応）

## 🔄 CI/CDパイプライン統合例

### GitHub Actions（推奨例）
```yaml
name: Test and Release

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test-action:
    name: Run security check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.x'
          cache: 'pip'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Run security check
        id: security-check
        uses: ./
        continue-on-error: true
        with:
          target: '.'
          severity: 'LOW'
          html-output: 'reports'
          fail-on-severity: 'CRITICAL'
      - name: Upload security reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: reports/
          retention-days: 7
          if-no-files-found: warn
  auto-tag:
    name: Create Auto Tag
    needs: test-action
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      # ...タグ生成処理...
  create-release:
    name: Create Release
    needs: auto-tag
    if: needs.auto-tag.result == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ needs.auto-tag.outputs.new_tag }}
      - name: Download security reports
        uses: actions/download-artifact@v4
        continue-on-error: true
        with:
          name: security-reports
          path: reports/
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          tag_name: ${{ needs.auto-tag.outputs.new_tag }}
          name: バージョン ${{ needs.auto-tag.outputs.new_tag }} - リリース ${{ needs.auto-tag.outputs.release_date }}
          files: |
            reports/*
```

### PRコメント自動投稿例
```yaml
      - name: Run PR comment example
        if: ${{ github.event.pull_request.number != '' }}
        run: bash ci_templates/pr_comment_example.sh ${{ github.event.pull_request.number }} "CI自動コメントテスト"
        env:
          GH_TOKEN: ${{ github.token }}
      - name: Post PR comment
        if: ${{ github.event.pull_request.number != '' }}
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: ${{ github.event.pull_request.number }}
          body-file: pr_comment.txt
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

- 独自の危険なパターンの追加が可能（custom_rules.json編集）
- セキュリティチェックの重要度閾値の調整
- レポート形式のカスタマイズ
- 通知サービス（Slack/Discord/Teams/Google Chat）設定

## 📈 今後の予定

- [ ] より多くのセキュリティパターンの追加
- [ ] パフォーマンスの最適化
- [ ] さらなるCI/CDツールとの統合
- [ ] カスタムルールの設定ファイル対応

## 🤝 コントリビューション

バグ報告や機能要望は、Issueを作成してください。プルリクエストも歓迎です。

## 📄 ライセンス

MITライセンスの下で公開されています。

## 脆弱性データベース自動更新・新CVE通知

- NVD（米国脆弱性データベース）から最新CVE情報を自動取得し、依存パッケージと突き合わせて新たな脆弱性を検出・通知します。
- Slack通知にも対応。

### 使い方

1. NVDからCVEデータベースを取得・更新

```sh
python code_checker.py 任意のファイル.py --update-cve-db
```

2. requirements.txtの依存パッケージとCVEデータベースを突き合わせて新規脆弱性を通知

```sh
python code_checker.py 任意のファイル.py --check-cve
```

- 新たなCVEが見つかった場合は標準出力とSlack（notifier_config.json設定時）に通知されます。
- 通知済みCVEはlast_cve_notify.jsonで管理され、重複通知を防止します。

### 注意
- NVD APIの仕様上、取得件数や期間は適宜調整してください。
- requirements.txtのパッケージ名とNVDの製品名が完全一致しない場合、一部検出できないことがあります。
- Slack通知にはnotifier_config.jsonの設定が必要です。
