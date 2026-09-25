import json
import sqlite3
import time
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS bonds (id TEXT PRIMARY KEY, expires INTEGER, revoked INTEGER NOT NULL DEFAULT 0, capsule TEXT NOT NULL)")
        Path(self.path).chmod(0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def accept(self, capsule):
        try:
            with self.connect() as db:
                db.execute("INSERT INTO bonds(id,expires,capsule) VALUES (?,?,?)",
                    (capsule["bond_id"], capsule["expires_at"], json.dumps(capsule)))
        except sqlite3.IntegrityError:
            raise ValueError("Replay or revoked bond") from None

    def read(self, bond_id):
        with self.connect() as db:
            row = db.execute("SELECT expires,revoked,capsule FROM bonds WHERE id=?", (bond_id,)).fetchone()
        if not row or row[1] or int(time.time()) >= row[0]:
            raise ValueError("Unknown, revoked or expired bond")
        return json.loads(row[2])

    def revoke(self, bond_id):
        with self.connect() as db:
            db.execute("INSERT INTO bonds(id,expires,revoked,capsule) VALUES (?,0,1,'{}') ON CONFLICT(id) DO UPDATE SET revoked=1, capsule='{}'", (bond_id,))
