"""
AXERONIX XDR Copilot — Module 2: Event Correlation Engine

Turns a stream of normalized events (Module 1's output shape) into a
small number of labeled, explainable incidents.

Public entry point: CorrelationEngine
"""

from .engine import CorrelationEngine
from .schema import Event, Alert, Session, Incident

__all__ = ["CorrelationEngine", "Event", "Alert", "Session", "Incident"]
