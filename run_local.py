#!/usr/bin/env python3
"""Local Server Launcher for AMANA SHIELD.

Launches the application locally on http://127.0.0.1:8000 using SQLite and Uvicorn.
Requires no Docker, no PostgreSQL installation, and no external API keys.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings


def start_local_server() -> None:
    settings = get_settings()

    print(
        r"""
==============================================================================
    ___    __  ______    _   _____         _____ __  __________________ 
   /   |  /  |/  /   |  / | / /   |       / ___// / / /  _/ ____/ / __ \
  / /| | / /|_/ / /| | /  |/ / /| | _____ \__ \/ /_/ // // __/ / / / / /
 / ___ |/ /  / / ___ |/ /|  / ___ |/_____/__/ / __  // // /___/ / /_/ / 
/_/  |_/_/  /_/_/  |_/_/ |_/_/  |_|     /____/_/ /_/___/_____/_/_____/  
==============================================================================
AMANA SHIELD is running LOCALLY!

[*] Public Verification Portal: http://127.0.0.1:8000
[*] Analyst Dashboard:          http://127.0.0.1:8000/analyst
[*] Interactive API Swagger UI: http://127.0.0.1:8000/api/v1/docs
[*] System Healthcheck Probe:   http://127.0.0.1:8000/api/v1/health

Key: Analyst API Key (for Analyst Dashboard):
   amana_analyst_secret_token_12345

Features Active:
   - Database: Local SQLite (amana_local.db)
   - Triage Engine: Deterministic URL/Domain Intelligence
   - AI Engine: Local Deterministic Heuristic Fallback (Zero external cost)
   - Fact-Checking Evidence: Curated Nigerian Institutional DB (INEC, FGN, NIMC)
   - Press Ctrl+C in this terminal anytime to stop the server.
==============================================================================
"""
    )

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    start_local_server()
