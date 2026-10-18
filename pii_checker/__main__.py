"""python -m pii_checker の入口。"""

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()  # exe 化したときにワーカープロセスを起動できるようにする
    from pii_checker.cli import main

    sys.exit(main(sys.argv[1:]))
