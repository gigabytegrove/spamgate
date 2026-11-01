"""Fail-closed transport evidence handoff regressions (synthetic only)."""
import copy
import unittest
from spamgate_evidence_chain import validate_transport_chain

RID = "a" * 32
SUCCESS = "transport_sent_not_mailbox_verified"


def valid():
    entry = {"case_id": "ham1", "run_id": RID, "queue_id": "A1B2C3",
             "state": SUCCESS, "queue_removed": True, "held": False,
             "discarded": False, "sent_count": 1,
             "transport_events": [{"transport": "lmtp", "status": "sent"}]}
    return {"counts": {SUCCESS: 1},
            "log_chronology": {"chronology_validated": True, "lines": 3},
            "entries": [entry]}


class EvidenceChainTests(unittest.TestCase):
    def test_valid_chain(self):
        e = valid()
        self.assertTrue(validate_transport_chain(e, e["entries"]))

    def test_yearless_or_missing_timestamp_provenance_not_falsely_certified(self):
        e = valid()
        e["log_chronology"]["chronology_validated"] = False
        self.assertFalse(validate_transport_chain(e, e["entries"]))

    def assert_refused(self, edit):
        e = valid()
        edit(e)
        with self.assertRaises(ValueError):
            validate_transport_chain(e, e["entries"])

    def test_false_summary_flag_count(self):
        self.assert_refused(lambda e: e["counts"].update({SUCCESS: 2}))

    def test_missing_counts(self):
        self.assert_refused(lambda e: e.pop("counts"))

    def test_boolean_count_not_integer(self):
        self.assert_refused(lambda e: e["counts"].update({SUCCESS: True}))

    def test_missing_chronology(self):
        self.assert_refused(lambda e: e.pop("log_chronology"))

    def test_fake_chronology_type(self):
        self.assert_refused(lambda e: e["log_chronology"].update({"chronology_validated": "true"}))

    def test_removed_flag_missing(self):
        self.assert_refused(lambda e: e["entries"][0].pop("queue_removed"))

    def test_removed_flag_false(self):
        self.assert_refused(lambda e: e["entries"][0].update({"queue_removed": False}))

    def test_held_flag_true(self):
        self.assert_refused(lambda e: e["entries"][0].update({"held": True}))

    def test_discarded_flag_true(self):
        self.assert_refused(lambda e: e["entries"][0].update({"discarded": True}))

    def test_sent_count_boolean(self):
        self.assert_refused(lambda e: e["entries"][0].update({"sent_count": True}))

    def test_duplicate_sent_count(self):
        self.assert_refused(lambda e: e["entries"][0].update({"sent_count": 2}))

    def test_no_sent_event(self):
        self.assert_refused(lambda e: e["entries"][0].update({"transport_events": [{"transport": "lmtp", "status": "deferred"}]}))

    def test_discard_transport(self):
        self.assert_refused(lambda e: e["entries"][0].update({"transport_events": [{"transport": "discard", "status": "sent"}]}))

    def test_error_transport(self):
        self.assert_refused(lambda e: e["entries"][0].update({"transport_events": [{"transport": "error", "status": "sent"}]}))

    def test_bounce_after_sent(self):
        self.assert_refused(lambda e: e["entries"][0]["transport_events"].append({"transport": "lmtp", "status": "bounced"}))

    def test_duplicate_sent_events(self):
        self.assert_refused(lambda e: e["entries"][0]["transport_events"].append({"transport": "smtp", "status": "sent"}))

    def test_extra_event_keys(self):
        self.assert_refused(lambda e: e["entries"][0]["transport_events"][0].update({"secret": "ignored"}))

    def test_invalid_run_identity(self):
        self.assert_refused(lambda e: e["entries"][0].update({"run_id": "../etc/passwd"}))

    def test_valid_retry_then_success(self):
        e = valid()
        e["entries"][0]["transport_events"].insert(0, {"transport": "smtp", "status": "deferred"})
        self.assertTrue(validate_transport_chain(e, e["entries"]))


if __name__ == "__main__":
    unittest.main()
