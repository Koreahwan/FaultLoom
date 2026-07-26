"""Make the isolated future Cloud pack source available only to its tests."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACK_SOURCE = ROOT / "packs" / "cloud" / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PACK_SOURCE))
