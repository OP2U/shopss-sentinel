# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import sqlite3


def main() -> None:
    parser = argparse.ArgumentParser(description="View private SHOPSS Sentinel events")
    parser.add_argument(
        "--db",
        default="/var/lib/shopss-sentinel/sentinel.db",
        help="Path to Sentinel SQLite database"
    )
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    con = sqlite3.connect(args.db)

    rows = con.execute(
        """
        SELECT id, created_at, severity, event_type, message, metadata_json
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, args.limit),),
    ).fetchall()

    print()
    print("SHOPSS SENTINEL - PRIVATE EVENT VIEWER")
    print("=" * 118)

    for event_id, created_at, severity, event_type, message, metadata_json in rows:
        extra = ""

        if metadata_json:
            try:
                metadata = json.loads(metadata_json)
            except json.JSONDecodeError:
                metadata = {}

            details = []

            if metadata.get("source_ip"):
                details.append(f"source={metadata['source_ip']}")
            if metadata.get("username"):
                details.append(f"user={metadata['username']}")
            if metadata.get("path"):
                details.append(f"path={metadata['path']}")
            if metadata.get("event_count") is not None:
                details.append(f"count={metadata['event_count']}")
            if metadata.get("block_minutes") is not None:
                details.append(f"block={metadata['block_minutes']}m")
            if metadata.get("result"):
                details.append(f"result={metadata['result']}")

            if details:
                extra = " | " + " ".join(details)

        print(
            f"{event_id} | {created_at} | {severity.upper():8} | "
            f"{event_type:20} | {message}{extra}"
        )

    con.close()


if __name__ == "__main__":
    main()
