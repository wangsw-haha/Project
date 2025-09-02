"""
Industrial Internet Honeypot with LLM-based Dynamic Response System
"""

import sys
from pathlib import Path

# Add src directory to Python path for imports
if __name__ != "__main__":
    src_path = Path(__file__).parent
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

__version__ = "1.0.0"