# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""API module for Skill Scanner.

This module provides a FastAPI application for scanning agent skills packages.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

from .. import __version__ as PACKAGE_VERSION
from .router import router as api_router

# Load .env file with priority: current dir -> home dir -> parent dirs
def _load_env_file():
    """Load .env file from multiple possible locations."""
    search_paths = [
        Path.cwd() / ".env",  # Current working directory
        Path.home() / ".env",  # User home directory
    ]
    
    # Add parent directories (up to 3 levels)
    current = Path.cwd()
    for _ in range(3):
        current = current.parent
        search_paths.append(current / ".env")
    
    for env_path in search_paths:
        if env_path.exists():
            load_dotenv(env_path, override=False)
            break

_load_env_file()

app = FastAPI(
    title="Skill Scanner API",
    description="Security scanning API for agent skills packages",
    version=PACKAGE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(api_router)
