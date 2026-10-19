"""exe（アプリ版・窓）の入口。引数があっても窓を開く（フォルダやファイルのパスは検査の対象に入れる）。"""

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()  # 検査用のワーカープロセスを exe から起動できるようにする
    from pii_checker.cli import app_main

    sys.exit(app_main(sys.argv[1:]))
