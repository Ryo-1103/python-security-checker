# GitHub CLI（gh）を使ったPR自動コメント例
# 環境変数GITHUB_TOKENが必要
# 例: ./pr_comment_example.sh <PR番号> <コメント内容>

PR_NUMBER=$1
COMMENT=$2

if [ -z "$PR_NUMBER" ]; then
  echo "PR番号が指定されていないためコメント投稿をスキップします。"
  exit 0
fi

gh pr comment $PR_NUMBER --body "$COMMENT"
