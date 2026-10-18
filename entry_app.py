"""exe（アプリ版・窓）の入口。引数を付ければ CLI と同じ指定もできる。"""

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()  # 検査用のワーカープロセスを exe から起動できるようにする
    from pii_checker.cli import main

    sys.exit(main(sys.argv[1:] or ["app"]))
