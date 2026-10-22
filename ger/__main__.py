"""python3 -I ger/__main__.py で起動する（-I のためリポジトリのルートを明示的に追加。追加するのは GER 自身の場所だけ）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from ger.cli import main  # noqa: E402

sys.exit(main())
