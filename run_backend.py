import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import uvicorn

if __name__ == "__main__":
    os.chdir(ROOT_DIR)
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
