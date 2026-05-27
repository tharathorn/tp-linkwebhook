#!/usr/bin/env python3
import os
from pathlib import Path

from event_model import EventStore

db_path = Path(os.environ.get("WEBHOOK_DB", "/var/lib/omada-webhook/events.sqlite3"))
store = EventStore(db_path)
backfilled = store.backfill()
renormalized = store.renormalize()
print(f"backfilled={backfilled} renormalized={renormalized}")
