"""Thread-local context for the active pentest run.

Set at the start of `_run_pipeline` in server/main.py, read by
finding_reporter_tool when persisting findings to the DB.
"""

import threading
from typing import Optional, Tuple

_local = threading.local()


def set_run_context(run_id: Optional[int], user_id: Optional[int]) -> None:
    _local.run_id = run_id
    _local.user_id = user_id


def clear_run_context() -> None:
    _local.run_id = None
    _local.user_id = None


def get_run_context() -> Tuple[Optional[int], Optional[int]]:
    return getattr(_local, "run_id", None), getattr(_local, "user_id", None)
