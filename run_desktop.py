from __future__ import annotations

import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


def main() -> None:
    # Keep .env and the SQLite data directory beside the executable when packaged.
    base_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    os.chdir(base_dir)

    import uvicorn
    from app.main import app

    url = "http://127.0.0.1:8765"

    def open_browser() -> None:
        time.sleep(1.5)
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()
    print("NetScope Pro is running locally at", url)
    print("Press Ctrl+C to stop. Do not expose this service to the internet.")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")


if __name__ == "__main__":
    main()
