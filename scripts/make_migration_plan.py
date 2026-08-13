#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from app.migration_plan import plan_from_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a paced manual recovery plan from an account inventory backup.")
    parser.add_argument("inventory", type=Path, help="Path to account-inventory-*.json")
    parser.add_argument("output", type=Path, nargs="?", default=Path("/app/backups/migration-plan.json"))
    parser.add_argument("--minutes", type=int, default=30, help="Target pacing window, clamped to 20-40 minutes")
    args = parser.parse_args()
    path = plan_from_file(args.inventory, args.output, args.minutes)
    print(path)


if __name__ == "__main__":
    main()
