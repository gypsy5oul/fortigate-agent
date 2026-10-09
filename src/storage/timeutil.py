"""Timestamp utilities ensuring timezone-aware UTC datetime for asyncpg and storage."""

from datetime import datetime, timezone
from typing import Union, Optional


def to_utc_datetime(val: Union[int, float, str, datetime, None]) -> datetime:
    """Convert int/float (ns or s), ISO string, or datetime into timezone-aware UTC datetime."""
    if val is None:
        return datetime.now(timezone.utc)
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, (int, float)):
        # If timestamp is nanoseconds (e.g. > 1e14), convert to seconds
        if val > 1e14:
            return datetime.fromtimestamp(val / 1e9, tz=timezone.utc)
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        val_clean = val.strip()
        if not val_clean:
            return datetime.now(timezone.utc)
        try:
            # Handle ISO formats, replace Z with +00:00
            dt = datetime.fromisoformat(val_clean.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            try:
                ts = float(val_clean)
                return to_utc_datetime(ts)
            except Exception:
                return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)
