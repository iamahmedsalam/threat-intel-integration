import sqlite3
import json
import time
import logging

logger = logging.getLogger("enrichment")


class EnrichmentCache:

    def __init__(self, db_path="cache/enrichment_cache.db", ttl=3600):
        self.db_path = db_path
        self.ttl = ttl
        self.conn = sqlite3.connect(db_path)
        self.create_table()
        logger.info(f"Cache initialized (TTL={ttl}s)")

    def create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                ip TEXT PRIMARY KEY,
                result TEXT,
                timestamp REAL
            )
        """)
        self.conn.commit()

    def get(self, ip):
        cursor = self.conn.execute(
            "SELECT result, timestamp FROM cache WHERE ip = ?",
            (ip,)
        )
        row = cursor.fetchone()

        if row is None:
            return None

        result_json, cached_time = row

        if time.time() - cached_time > self.ttl:
            logger.info(f"Cache expired for {ip}")
            self.delete(ip)
            return None

        logger.info(f"Cache hit for {ip}")
        return json.loads(result_json)

    def set(self, ip, result):
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (ip, result, timestamp) VALUES (?, ?, ?)",
            (ip, json.dumps(result), time.time())
        )
        self.conn.commit()
        logger.info(f"Cached result for {ip}")

    def delete(self, ip):
        self.conn.execute("DELETE FROM cache WHERE ip = ?", (ip,))
        self.conn.commit()

    def close(self):
        self.conn.close()
