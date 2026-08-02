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

"""Support for Argus log files (Rust implementation via subprocess)"""

import datetime
import json
import subprocess
from typing import Any, BinaryIO

from ivre.parser import CmdParser


class Argus(CmdParser):
    """Argus log generator (Rust implementation via subprocess)"""

    fields = [
        "proto",
        "dir",
        "saddr",
        "sport",
        "daddr",
        "dport",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "stime",
        "ltime",
    ]
    aggregation = ["saddr", "sport", "daddr", "dport", "proto"]
    timefmt = "%s.%f"

    def __init__(self, fdesc: str | BinaryIO, pcap_filter: str | None = None):
        """Creates the Argus object.

        fdesc: a file-like object or a filename
        pcap_filter: a PCAP filter to use with racluster (not supported in Rust version)
        """
        if pcap_filter is not None:
            from ivre.utils import LOGGER
            LOGGER.warning("PCAP filter not supported in Rust Argus parser")
        
        self.fdesc = fdesc if isinstance(fdesc, str) else None
        self.file_handle = fdesc if not isinstance(fdesc, str) else None
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
        
        binary_name = "ivre-argus-parser"
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
        
        if self.fdesc:
            # File path provided
            input_path = self.fdesc
        elif self.file_handle:
            # File-like object provided - write to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.log') as tmp:
                tmp.write(self.file_handle.read())
                input_path = tmp.name
        else:
            raise ValueError("No valid file descriptor provided")
        
        try:
            result = subprocess.run(
                [binary_path, input_path],
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
        finally:
            # Clean up temp file if we created one
            if self.file_handle and 'input_path' in locals() and input_path != self.fdesc:
                import os
                try:
                    os.unlink(input_path)
                except:
                    pass

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

    @classmethod
    def parse_line(cls, line: bytes) -> dict[str, Any]:
        """Parse a single line (not supported in subprocess version)"""
        raise NotImplementedError("Single line parsing not supported in subprocess version. Use full file parsing instead.")
