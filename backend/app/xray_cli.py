from __future__ import annotations

import argparse

from app.database import SessionLocal
from app.services.xray_manager import PROTOCOLS, sync_xray_users, write_config


def main() -> int:
    parser = argparse.ArgumentParser(description="VPN Panel Xray configuration helper")
    parser.add_argument("command", choices=("generate", "sync"))
    parser.add_argument("--protocol", choices=PROTOCOLS)
    args = parser.parse_args()
    protocols = (args.protocol,) if args.protocol else PROTOCOLS
    db = SessionLocal()
    try:
        if args.command == "generate":
            for protocol in protocols:
                print(write_config(db, protocol))
        else:
            print(sync_xray_users(db, protocols=protocols, restart=True))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
