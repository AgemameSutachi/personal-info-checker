"""試験の全体に効く準備。"""

import os

# git のフック（pre-push など）の中から試験を流すと、GIT_DIR などが渡ってくる。残したままだと、試験が一時の
# フォルダに作るリポジトリへの git の操作が、このリポジトリ本体へ当たる（2026-11-06 に worktree からの push で
# 実際に起きた）。試験の始まる前に外しておく（tools/prepush_check.py でも外している）。
for _name in [k for k in os.environ if k.upper().startswith("GIT_")]:
    del os.environ[_name]
