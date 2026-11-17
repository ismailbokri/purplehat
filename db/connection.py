"""PostgreSQL connection helpers.

Reads the PFE_DB_* env vars, so a single Postgres instance hosts the
user/auth/checklist/findings tables (and, where present, any pgvector index).
"""

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


def get_db_config() -> Dict[str, Any]:
    return {
        "dbname":   os.getenv("PFE_DB_NAME"),
        "user":     os.getenv("PFE_DB_USER"),
        "password": os.getenv("PFE_DB_PASSWORD"),
        "host":     os.getenv("PFE_DB_HOST"),
        "port":     os.getenv("PFE_DB_PORT"),
    }


@contextmanager
def get_conn() -> Iterator[psycopg2.extensions.connection]:
    """Open a connection, commit on clean exit, rollback on exception, always close."""
    conn = psycopg2.connect(**get_db_config())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def get_dict_cursor() -> Iterator[psycopg2.extras.DictCursor]:
    """Convenience: connection + DictCursor in one context manager."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            yield cur
