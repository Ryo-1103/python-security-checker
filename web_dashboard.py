import os
import json
import glob
from flask import Flask, render_template, send_from_directory

app = Flask(__name__)

@app.route('/')
def dashboard():
    # historyディレクトリ内の最新JSONファイルを探す
    history_dir = os.path.join(os.path.dirname(__file__), 'history')
    json_files = sorted(glob.glob(os.path.join(history_dir, '*.json')))
    if not json_files:
        return '診断結果ファイルがありません。code_checker.pyを先に実行してください。'
    result_path = json_files[-1]  # 最新ファイル
    with open(result_path, encoding='utf-8') as f:
        results = json.load(f)
    return render_template('dashboard.html', results=results)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(debug=True)
