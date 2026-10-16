import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import vt_domain_monitor as monitor


def valid_env(**overrides):
    env = {
        "VT_API_KEY": "secret",
        "VT_DOMAINS": "example.org, your-gitlab.eu",
        "SMTP_HOST": "smtp.example.org",
        "SMTP_FROM": "monitor@example.org",
        "SMTP_RECIPIENTS": "security@example.org",
    }
    env.update(overrides)
    return env


class ConfigTests(unittest.TestCase):
    def test_loads_and_normalizes_config(self):
        config = monitor.load_config(valid_env(VT_DOMAINS="EXAMPLE.ORG.,example.org"))
        self.assertEqual(config.domains, ("example.org",))
        self.assertEqual(config.domain_delay_seconds, 60)

    def test_rejects_delay_below_one_minute(self):
        with self.assertRaisesRegex(monitor.ConfigurationError, "at least 60"):
            monitor.load_config(valid_env(VT_DOMAIN_DELAY_SECONDS="59"))

    def test_rejects_invalid_domain(self):
        with self.assertRaisesRegex(monitor.ConfigurationError, "Invalid domain"):
            monitor.load_config(valid_env(VT_DOMAINS="https://example.org/path"))

    def test_offline_mode_does_not_require_vt_configuration(self):
        env = valid_env()
        del env["VT_API_KEY"]
        del env["VT_DOMAINS"]
        config = monitor.load_config(env, require_virustotal=False)
        self.assertEqual(config.api_key, "")
        self.assertEqual(config.domains, ())


class AnalysisTests(unittest.TestCase):
    def test_extracts_only_malicious_and_suspicious_engines(self):
        attributes = {
            "stats": {"malicious": 1, "suspicious": 1, "harmless": 1},
            "results": {
                "Engine A": {"category": "malicious", "result": "phishing"},
                "Engine B": {"category": "harmless", "result": "clean"},
                "Engine C": {"engine_name": "Vendor C", "category": "suspicious", "result": "riskware"},
            },
        }
        result = monitor.parse_completed_analysis("example.org", "analysis-id", attributes)
        self.assertTrue(result.is_flagged)
        self.assertEqual([(f.engine, f.result) for f in result.findings], [("Engine A", "phishing"), ("Vendor C", "riskware")])

    def test_clean_sample_shape_is_not_flagged(self):
        attributes = {
            "stats": {"malicious": 0, "suspicious": 0, "undetected": 36, "harmless": 54, "timeout": 0},
            "results": {"Acronis": {"engine_name": "Acronis", "category": "harmless", "result": "clean"}},
        }
        result = monitor.parse_completed_analysis("your-gitlab.eu", "analysis-id", attributes)
        self.assertFalse(result.is_flagged)
        self.assertEqual(result.findings, ())

    def test_jsonl_alert_contains_engine_results(self):
        result = monitor.ScanResult(
            "bad.example", "id-1", {"malicious": 1, "suspicious": 0},
            (monitor.Finding("Example AV", "malicious", "phishing"),),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.jsonl"
            monitor.append_alert(path, result)
            entry = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(entry["domain"], "bad.example")
        self.assertEqual(entry["findings"][0]["result"], "phishing")

    def test_parses_saved_domain_analysis_payload(self):
        payload = {
            "data": {
                "id": "analysis-id",
                "links": {"item": "https://www.virustotal.com/api/v3/domains/fallback.example"},
                "attributes": {
                    "status": "completed",
                    "stats": {"malicious": 0, "suspicious": 1},
                    "results": {"Vendor": {"category": "suspicious", "result": "suspicious"}},
                },
            },
            "meta": {"netloc_info": {"id": "EXAMPLE.ORG"}},
        }
        result = monitor.parse_analysis_payload(payload)
        self.assertEqual(result.domain, "example.org")
        self.assertTrue(result.is_flagged)

    def test_saved_analysis_requires_completed_status(self):
        payload = {"data": {"id": "analysis-id", "attributes": {"status": "queued"}}}
        with self.assertRaisesRegex(monitor.VirusTotalError, "must have status 'completed'"):
            monitor.parse_analysis_payload(payload)


class RequestTests(unittest.TestCase):
    def test_submit_uses_expected_endpoint_and_header(self):
        config = monitor.load_config(valid_env())
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":{"id":"abc"}}'
        opener = mock.Mock(return_value=response)
        client = monitor.VirusTotalClient(config, opener=opener)
        self.assertEqual(client.submit_domain("example.org"), "abc")
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, "https://www.virustotal.com/api/v3/domains/example.org/analyse")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("X-apikey"), "secret")

    def test_polling_waits_for_completed_analysis(self):
        config = monitor.load_config(valid_env(VT_POLL_INTERVAL_SECONDS="7"))
        queued = mock.MagicMock()
        queued.__enter__.return_value.read.return_value = b'{"data":{"attributes":{"status":"queued"}}}'
        completed = mock.MagicMock()
        completed.__enter__.return_value.read.return_value = (
            b'{"data":{"attributes":{"status":"completed","stats":{"malicious":0,"suspicious":0},"results":{}}}}'
        )
        sleep = mock.Mock()
        client = monitor.VirusTotalClient(config, opener=mock.Mock(side_effect=[queued, completed]), sleep=sleep)
        result = client.wait_for_analysis("example.org", "abc")
        self.assertFalse(result.is_flagged)
        sleep.assert_called_once_with(7)


class RunnerTests(unittest.TestCase):
    @mock.patch.object(monitor, "send_alert")
    @mock.patch.object(monitor, "append_alert")
    @mock.patch.object(monitor.VirusTotalClient, "wait_for_analysis")
    @mock.patch.object(monitor.VirusTotalClient, "submit_domain")
    def test_flagged_domain_is_printed_logged_and_emailed(self, submit, wait, append, send):
        config = monitor.load_config(valid_env(VT_DOMAINS="bad.example"))
        finding = monitor.Finding("Example AV", "malicious", "phishing")
        result = monitor.ScanResult("bad.example", "id-1", {"malicious": 1, "suspicious": 0}, (finding,))
        submit.return_value = "id-1"
        wait.return_value = result
        with mock.patch("builtins.print") as output:
            self.assertEqual(monitor.run(config), 0)
        output.assert_called_once()
        append.assert_called_once_with(config.alert_log, result)
        send.assert_called_once_with(config, result)


if __name__ == "__main__":
    unittest.main()
