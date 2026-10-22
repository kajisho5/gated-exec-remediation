"""操作レジストリ。ここに登録されていない操作種別は G-5 で拒否する。

write_config / rotate_secret は設計（対象形式・外部サービスの扱い）が固まるまで登録しない。
"""
from . import chmod

REGISTRY = {chmod.TYPE: chmod}
