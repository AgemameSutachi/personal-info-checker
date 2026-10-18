"""exe（コマンド版）の入口。"""

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from pii_checker.cli import main

    sys.exit(main(sys.argv[1:]))
