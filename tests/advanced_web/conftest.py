"""Make this isolated future-pack source tree available to its focused tests only."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACK_SOURCE = ROOT / "packs" / "advanced_web" / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PACK_SOURCE))
