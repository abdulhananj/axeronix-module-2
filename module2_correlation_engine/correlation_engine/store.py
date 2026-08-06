"""
In-memory store for correlated incidents, matching the "Redis"
line in Module 2's core stack.

Real Redis is optional: if the `redis` package and a server are
available, IncidentStore uses it (as a JSON-per-key store) so
downstream modules (Module 3, Module 6, Module 9...) can read
incidents from a shared, fast store instead of only in-process
memory. If Redis isn't available, it transparently falls back to a
plain dict so the engine still runs standalone (e.g. in tests, or a
laptop demo with nothing else installed).
"""

from __future__ import annotations

import json
from typing import Optional

from .schema import Incident

_KEY_PREFIX = "axeronix:incident:"


class IncidentStore:
    def __init__(self, redis_url: Optional[str] = None):
        self._redis = None
        self._memory: dict[str, dict] = {}

        if redis_url:
            try:
                import redis  # type: ignore

                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                # Redis not reachable/installed — fall back silently,
                # the engine should still work in a bare environment.
                self._redis = None

    def save(self, incident: Incident) -> None:
        payload = json.dumps(incident.to_dict())
        if self._redis is not None:
            self._redis.set(_KEY_PREFIX + incident.incident_id, payload)
        else:
            self._memory[incident.incident_id] = json.loads(payload)

    def save_all(self, incidents: list[Incident]) -> None:
        for incident in incidents:
            self.save(incident)

    def get(self, incident_id: str) -> Optional[dict]:
        if self._redis is not None:
            raw = self._redis.get(_KEY_PREFIX + incident_id)
            return json.loads(raw) if raw else None
        return self._memory.get(incident_id)

    def all_ids(self) -> list[str]:
        if self._redis is not None:
            keys = self._redis.keys(_KEY_PREFIX + "*")
            return [k[len(_KEY_PREFIX):] for k in keys]
        return list(self._memory.keys())

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"
