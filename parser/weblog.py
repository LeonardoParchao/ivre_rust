# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

"""Support for http server log files (Rust implementation via subprocess)"""

import datetime
import json
import subprocess
from typing import Any

from ivre.parser import Parser


class WeblogFile(Parser):
    """Http server log generator (Rust implementation via subprocess)"""

    def __init__(self, fname: str) -> None:
        """Init WeblogFile class."""
        self.fname = fname
        self._results = None
        self._result_iter = None

    def __iter__(self):
        if self._results is None:
            self._parse_file()
        return self

    def __next__(self):
        if self._results is None:
            self._parse_file()
        if self._result_iter is None:
            self._result_iter = iter(self._results)
        try:
            return next(self._result_iter)
        except StopIteration:
            raise StopIteration

    def _parse_file(self):
        """Parse file using Rust binary"""
        import shutil
        
        binary_name = "ivre-weblog-parser"
        binary_path = shutil.which(binary_name)
        
        if binary_path is None:
            # Try to find it in the target directory
            import os
            script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            possible_path = os.path.join(script_dir, "target", "debug", f"{binary_name}.exe")
            if os.path.exists(possible_path):
                binary_path = possible_path
            else:
                raise RuntimeError(f"Could not find {binary_name} binary. Please build it with: cargo build --release")
        
        try:
            result = subprocess.run(
                [binary_path, self.fname],
                capture_output=True,
                text=True,
                check=True
            )
            
            self._results = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        parsed = json.loads(line)
                        # Convert to match Python format
                        self._results.append(self._convert_result(parsed))
                    except json.JSONDecodeError:
                        continue
        except subprocess.CalledProcessError as e:
            from ivre.utils import LOGGER
            LOGGER.error(f"Error running Rust parser: {e.stderr}")
            self._results = []

    def _convert_result(self, result: dict) -> dict[str, Any]:
        """Convert Rust result to Python format"""
        converted = {}
        for key, value in result.items():
            if isinstance(value, str):
                converted[key] = value
            elif isinstance(value, (int, float)):
                converted[key] = value
            elif isinstance(value, bool):
                converted[key] = value
            elif value is None:
                converted[key] = None
            else:
                converted[key] = str(value)
        return converted

    def parse_line(self, line: bytes) -> dict[str, Any]:
        """Parse a single line (not supported in subprocess version)"""
        raise NotImplementedError("Single line parsing not supported in subprocess version. Use full file parsing instead.")
