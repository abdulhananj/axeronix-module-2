"""
Run with:  python -m pytest correlation_engine/tests -v
(or just:  python -m unittest discover correlation_engine/tests)
"""

import unittest
from datetime import datetime, timedelta, timezone

from correlation_engine.schema import Event
from correlation_engine.sessions import build_sessions
from correlation_engine.dedup import deduplicate_alerts
from correlation_engine.rules import (
    BruteForceRule, PhishingPayloadRule, PrivilegeEscalationRule,
    LateralMovementRule, run_rules,
)
from correlation_engine.grouping import group_alerts_into_incidents
from correlation_engine.killchain import build_kill_chain
from correlation_engine.engine import CorrelationEngine
from correlation_engine.module7_export import to_module7_input
from correlation_engine.sample_data import (
    brute_force_then_compromise, noisy_port_scan, lateral_movement, full_sample_dataset,
)

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class TestSessions(unittest.TestCase):
    def test_groups_by_host_and_window(self):
        events = [
            Event(T0, "HOST-A", "windows", "1", "a", user="u1"),
            Event(T0 + timedelta(seconds=30), "HOST-A", "windows", "1", "b", user="u1"),
            Event(T0 + timedelta(minutes=20), "HOST-A", "windows", "1", "c", user="u1"),  # new session
        ]
        sessions = build_sessions(events, window_seconds=300)
        self.assertEqual(len(sessions), 2)
        self.assertEqual(len(sessions[0].events), 2)
        self.assertEqual(len(sessions[1].events), 1)

    def test_empty_input(self):
        self.assertEqual(build_sessions([]), [])


class TestRules(unittest.TestCase):
    def test_brute_force_requires_min_failures(self):
        events = full_sample_dataset()
        sessions = build_sessions(brute_force_then_compromise())
        alerts = BruteForceRule().evaluate(sessions[0])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "brute_force_then_success")

    def test_phishing_payload_detects_office_parent(self):
        sessions = build_sessions(brute_force_then_compromise())
        alerts = PhishingPayloadRule().evaluate(sessions[0])
        self.assertEqual(len(alerts), 1)

    def test_privilege_escalation_requires_both_events(self):
        sessions = build_sessions(brute_force_then_compromise())
        alerts = PrivilegeEscalationRule().evaluate(sessions[0])
        self.assertEqual(len(alerts), 1)

    def test_no_false_positive_on_clean_session(self):
        clean = [Event(T0, "HOST-Z", "windows", "4624", "clean logon", user="nobody")]
        sessions = build_sessions(clean)
        alerts = run_rules(sessions)
        self.assertEqual(len(alerts), 0)

    def test_lateral_movement_needs_min_hosts(self):
        sessions = build_sessions(lateral_movement())
        alerts = LateralMovementRule().evaluate_all(sessions)
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(len(alerts[0].events), 3)


class TestDedup(unittest.TestCase):
    def test_collapses_repeated_alerts(self):
        sessions = build_sessions(noisy_port_scan())
        # port scan alone doesn't fire the brute-force rule (no success
        # login follows), so build synthetic repeats to test dedup directly
        from correlation_engine.schema import Alert
        e = Event(T0, "HOST-X", "firewall", "4625", "blocked", user=None)
        alerts = [
            Alert("test_rule", "desc", [e], host="HOST-X", user=None)
            for _ in range(10)
        ]
        deduped = deduplicate_alerts(alerts, window_seconds=60)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].count, 10)


class TestGrouping(unittest.TestCase):
    def test_related_alerts_merge_into_one_incident(self):
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].alerts), 4)

    def test_unrelated_alerts_stay_separate(self):
        events = brute_force_then_compromise() + lateral_movement()
        engine = CorrelationEngine()
        incidents = engine.run(events)
        self.assertEqual(len(incidents), 2)


class TestKillChain(unittest.TestCase):
    def test_stages_assigned_and_ordered(self):
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        chain = incidents[0].kill_chain
        stages = [s.stage for s in chain]
        self.assertIn("Persistence", stages)
        self.assertIn("Privilege Escalation", stages)
        timestamps = [s.event.timestamp for s in chain]
        self.assertEqual(timestamps, sorted(timestamps))


class TestFullPipeline(unittest.TestCase):
    def test_documented_expected_output(self):
        """Matches the module doc's own 'Expected Output' box exactly:
        one correlated incident, not four separate alerts."""
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        rule_names = {a.rule_name for a in inc.alerts}
        self.assertIn("brute_force_then_success", rule_names)
        self.assertIn("office_spawned_powershell", rule_names)
        self.assertIn("new_account_added_to_admins", rule_names)


class TestModule7Export(unittest.TestCase):
    def test_shape_matches_module7_contract(self):
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        incident_dict, timeline_dict = to_module7_input(incidents[0])

        for key in ("incident_id", "title", "kill_chain_summary", "severity", "events"):
            self.assertIn(key, incident_dict)
        for event in incident_dict["events"]:
            for key in ("event_id", "event_type", "timestamp", "kill_chain_stage", "host"):
                self.assertIn(key, event)

        self.assertIn("timeline", timeline_dict)
        self.assertEqual(timeline_dict["incident_id"], incident_dict["incident_id"])
        for i, entry in enumerate(timeline_dict["timeline"], start=1):
            self.assertEqual(entry["seq"], i)
            for key in ("event_id", "timestamp", "host", "label", "description"):
                self.assertIn(key, entry)

    def test_event_ids_are_unique_and_shared_across_incident_and_timeline(self):
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        incident_dict, timeline_dict = to_module7_input(incidents[0])

        incident_ids = [e["event_id"] for e in incident_dict["events"]]
        timeline_ids = [e["event_id"] for e in timeline_dict["timeline"]]
        self.assertEqual(len(incident_ids), len(set(incident_ids)))  # all unique
        self.assertEqual(incident_ids, timeline_ids)  # same order, same IDs

    def test_known_event_types_mapped_correctly(self):
        engine = CorrelationEngine()
        incidents = engine.run(brute_force_then_compromise())
        incident_dict, _ = to_module7_input(incidents[0])
        types_seen = {e["event_type"] for e in incident_dict["events"]}
        self.assertIn("logon_failed", types_seen)
        self.assertIn("logon_success", types_seen)
        self.assertIn("process_create", types_seen)
        self.assertNotIn("unclassified", types_seen)


if __name__ == "__main__":
    unittest.main()
