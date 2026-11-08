"""只读重评的命令行入口。逻辑在 `silver_sentinel.evalx`（随 wheel 发布）。

    python3 tools/eval_production.py --tier candidate,watch --allow-downgrade
    silver-sentinel eval-production --tier candidate --json
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from silver_sentinel.evalx import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
