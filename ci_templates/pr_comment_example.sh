# GitHub CLI（gh）を使ったPR自動コメント例
# 環境変数GITHUB_TOKENが必要
# 例: ./pr_comment_example.sh <PR番号> <コメント内容>

PR_NUMBER=$1
COMMENT=$2

gh pr comment $PR_NUMBER --body "$COMMENT"
