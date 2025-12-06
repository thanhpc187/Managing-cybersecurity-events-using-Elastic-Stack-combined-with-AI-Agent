import unittest

from ai.mitre_mapper import map_to_mitre


class TestMitreMapper(unittest.TestCase):
    def setUp(self):
        self.mapping = [
            {
                "id": "rule_bruteforce",
                "description": "bf",
                "tactic": "Credential Access",
                "technique": "T1110",
                "conditions": {
                    "login_failed_count_5m": "> 10",
                    "login_failed_ratio_5m": "> 0.8",
                },
            },
            {
                "id": "rule_remote_service",
                "description": "remote",
                "tactic": "Lateral Movement",
                "technique": "T1021",
                "conditions": {"destination.port": [22, 3389], "event.action": "allow"},
            },
        ]

    def test_bruteforce_match(self):
        alert = {"event.action": "deny"}
        features = {"login_failed_count_5m": 20, "login_failed_ratio_5m": 0.9}
        hits = map_to_mitre(alert, features, self.mapping)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["technique"], "T1110")

    def test_remote_service_match(self):
        alert = {"destination.port": 22, "event.action": "allow"}
        hits = map_to_mitre(alert, None, self.mapping)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["technique"], "T1021")

    def test_no_match(self):
        alert = {"destination.port": 80, "event.action": "allow"}
        hits = map_to_mitre(alert, None, self.mapping)
        self.assertEqual(len(hits), 0)


if __name__ == "__main__":
    unittest.main()

