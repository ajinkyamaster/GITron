"""Deterministic rest-day selection and session-shaped commit timestamps."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import random
from collections import defaultdict
from zoneinfo import ZoneInfo


def parse_window(value: str) -> tuple[dt.time, dt.time]:
    try:
        begin, finish = (dt.time.fromisoformat(part.strip()) for part in value.split("-", 1))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Working window must use HH:MM-HH:MM") from exc
    if dt.datetime.combine(dt.date.today(), finish) - dt.datetime.combine(dt.date.today(), begin) < dt.timedelta(hours=1):
        raise ValueError("Working window must be at least one hour and end on the same day")
    return begin, finish


def calendar_days(start: dt.date, days: int, working_days: tuple[int, ...], organic: bool,
                  seed: bytes) -> tuple[list[int], list[int]]:
    weekly = [day for day in range(1, days + 1)
              if (start + dt.timedelta(days=day - 1)).weekday() not in working_days]
    breaks: list[int] = []
    if organic:
        rng = random.Random(int.from_bytes(hashlib.sha256(seed + b"break-days").digest()[:8], "big"))
        for offset in range(0, days, 30):
            candidates = [day for day in range(max(2, offset + 2), min(days, offset + 30))
                          if day not in weekly and day not in {1, days}]
            count = min(len(candidates), 1 if days < 45 else rng.choice((1, 2)))
            breaks.extend(sorted(rng.sample(candidates, count)))
    rest = sorted(set(weekly + breaks))
    active = [day for day in range(1, days + 1) if day not in rest]
    return active, rest


def session_times(start: dt.date, zone: ZoneInfo, days: list[int], line_deltas: list[int],
                  weekday_window: str, weekend_window: str, seed: bytes, *, strict: bool = False) -> list[str]:
    rng = random.Random(int.from_bytes(hashlib.sha256(seed + b"session-times").digest()[:8], "big"))
    indices: dict[int, list[int]] = defaultdict(list)
    for index, day in enumerate(days):
        indices[day].append(index)
    timestamps = [""] * len(days)
    for day, positions in indices.items():
        date = start + dt.timedelta(days=day - 1)
        begin, finish = parse_window(weekday_window if date.weekday() < 5 else weekend_window)
        window_start = dt.datetime.combine(date, begin, tzinfo=zone)
        window_end = dt.datetime.combine(date, finish, tzinfo=zone)
        capacity = (window_end - window_start).total_seconds()
        intervals = [max(15, min(75, 14 + 6 * math.sqrt(max(1, line_deltas[index])) + rng.uniform(-6, 6))) * 60
                     for index in positions[1:]]
        if strict:
            intervals = [max(16 * 60, min(69 * 60, value)) for value in intervals]
            available = capacity - 120
            floor = 16 * 60
            if len(intervals) * floor > available:
                raise ValueError("Too many commits for a session with fifteen-minute gaps")
            if sum(intervals) > available:
                extra = sum(value - floor for value in intervals)
                scale = (available - len(intervals) * floor) / max(1, extra)
                intervals = [floor + (value - floor) * scale for value in intervals]
        if not strict and sum(intervals) > capacity - 900:
            factor = max(1, capacity - 900) / sum(intervals)
            intervals = [max(1, value * factor) for value in intervals]
        latest = max(0, capacity - sum(intervals) - 120)
        first = min(latest, max(0, rng.gauss(min(2400, latest / 2), min(1500, max(60, latest / 4)))))
        moment = window_start + dt.timedelta(seconds=first)
        previous = window_start - dt.timedelta(seconds=1)
        for offset, (position, interval) in enumerate(zip(positions, [0, *intervals])):
            moment += dt.timedelta(seconds=interval)
            moment = moment.replace(second=rng.randint(1, 59), microsecond=0)
            moment = max(moment, previous + dt.timedelta(seconds=1))
            latest_position = window_end - dt.timedelta(seconds=len(positions) - offset)
            if moment > latest_position:
                moment = latest_position
            timestamps[position] = moment.isoformat()
            previous = moment
    return timestamps
