#!/usr/bin/env python3
"""Submit VirusTotal domain scans and notify when vendors flag a domain."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable, Mapping


API_BASE_URL = "https://www.virustotal.com/api/v3"
DOMAIN_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
LOG = logging.getLogger("vt-domain-monitor")


class ConfigurationError(ValueError):
    """Raised when the environment configuration is invalid."""


class VirusTotalError(RuntimeError):
    """Raised when VirusTotal cannot complete an operation."""


@dataclass(frozen=True)
class Finding:
    engine: str
    category: str
    result: str


@dataclass(frozen=True)
class ScanResult:
    domain: str
    analysis_id: str
    stats: dict[str, int]
    findings: tuple[Finding, ...]

    @property
    def is_flagged(self) -> bool:
        return self.stats.get("malicious", 0) > 0 or self.stats.get("suspicious", 0) > 0


@dataclass(frozen=True)
class Config:
    api_key: str
    domains: tuple[str, ...]
    alert_log: Path
    domain_delay_seconds: float
    poll_interval_seconds: float
    analysis_timeout_seconds: float
    http_timeout_seconds: float
    max_http_retries: int
    smtp_host: str
    smtp_port: int
    smtp_security: str
    smtp_username: str | None
    smtp_password: str | None
    smtp_from: str
    smtp_recipients: tuple[str, ...]


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


def _number(env: Mapping[str, str], name: str, default: str, *, minimum: float) -> float:
    raw = env.get(name, default).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum:g}")
    return value


def _integer(env: Mapping[str, str], name: str, default: str, *, minimum: int) -> int:
    raw = env.get(name, default).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum}")
    return value


def _split_csv(raw: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigurationError(f"Invalid domain: {value!r}") from exc
    if not DOMAIN_RE.fullmatch(domain):
        raise ConfigurationError(f"Invalid domain: {value!r}")
    return domain


def load_config(env: Mapping[str, str] = os.environ, *, require_virustotal: bool = True) -> Config:
    if require_virustotal:
        domains = tuple(dict.fromkeys(normalize_domain(item) for item in _split_csv(_required(env, "VT_DOMAINS"))))
        if not domains:
            raise ConfigurationError("VT_DOMAINS must contain at least one domain")
        api_key = _required(env, "VT_API_KEY")
    else:
        domains = ()
        api_key = ""

    recipients = _split_csv(_required(env, "SMTP_RECIPIENTS"))
    security = env.get("SMTP_SECURITY", "starttls").strip().lower()
    if security not in {"starttls", "ssl", "none"}:
        raise ConfigurationError("SMTP_SECURITY must be starttls, ssl, or none")

    username = env.get("SMTP_USERNAME", "").strip() or None
    password = env.get("SMTP_PASSWORD", "") or None
    if bool(username) != bool(password):
        raise ConfigurationError("SMTP_USERNAME and SMTP_PASSWORD must be set together")

    return Config(
        api_key=api_key,
        domains=domains,
        alert_log=Path(env.get("VT_ALERT_LOG", "logs/alerts.jsonl")).expanduser(),
        domain_delay_seconds=_number(env, "VT_DOMAIN_DELAY_SECONDS", "60", minimum=60),
        poll_interval_seconds=_number(env, "VT_POLL_INTERVAL_SECONDS", "30", minimum=1),
        analysis_timeout_seconds=_number(env, "VT_ANALYSIS_TIMEOUT_SECONDS", "900", minimum=1),
        http_timeout_seconds=_number(env, "VT_HTTP_TIMEOUT_SECONDS", "30", minimum=1),
        max_http_retries=_integer(env, "VT_MAX_HTTP_RETRIES", "4", minimum=0),
        smtp_host=_required(env, "SMTP_HOST"),
        smtp_port=_integer(env, "SMTP_PORT", "587", minimum=1),
        smtp_security=security,
        smtp_username=username,
        smtp_password=password,
        smtp_from=_required(env, "SMTP_FROM"),
        smtp_recipients=recipients,
    )


class VirusTotalClient:
    def __init__(
        self,
        config: Config,
        *,
        sleep: Callable[[float], None] = time.sleep,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        self.config = config
        self.sleep = sleep
        self.opener = opener

    def _request_json(self, method: str, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{API_BASE_URL}{path}",
            method=method,
            headers={"x-apikey": self.config.api_key, "Accept": "application/json"},
            data=b"" if method == "POST" else None,
        )
        for attempt in range(self.config.max_http_retries + 1):
            try:
                with self.opener(request, timeout=self.config.http_timeout_seconds) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if retryable and attempt < self.config.max_http_retries:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        delay = max(float(retry_after), 1.0) if retry_after else min(2**attempt, 60)
                    except ValueError:
                        delay = min(2**attempt, 60)
                    LOG.warning("VirusTotal returned HTTP %s; retrying in %.0f seconds", exc.code, delay)
                    self.sleep(delay)
                    continue
                detail = exc.read().decode("utf-8", errors="replace")
                raise VirusTotalError(f"VirusTotal HTTP {exc.code}: {detail[:500]}") from exc
            except (urllib.error.URLError, TimeoutError, socket.timeout, json.JSONDecodeError) as exc:
                if attempt < self.config.max_http_retries:
                    delay = min(2**attempt, 60)
                    LOG.warning("VirusTotal request failed; retrying in %.0f seconds: %s", delay, exc)
                    self.sleep(delay)
                    continue
                raise VirusTotalError(f"VirusTotal request failed: {exc}") from exc
        raise AssertionError("unreachable")

    def submit_domain(self, domain: str) -> str:
        encoded_domain = urllib.parse.quote(domain, safe="")
        payload = self._request_json("POST", f"/domains/{encoded_domain}/analyse")
        try:
            return str(payload["data"]["id"])
        except (KeyError, TypeError) as exc:
            raise VirusTotalError("Domain submission response did not contain data.id") from exc

    def wait_for_analysis(self, domain: str, analysis_id: str) -> ScanResult:
        encoded_id = urllib.parse.quote(analysis_id, safe="")
        deadline = time.monotonic() + self.config.analysis_timeout_seconds
        while True:
            payload = self._request_json("GET", f"/analyses/{encoded_id}")
            try:
                attributes = payload["data"]["attributes"]
                status = attributes["status"]
            except (KeyError, TypeError) as exc:
                raise VirusTotalError("Analysis response is missing data.attributes.status") from exc

            if status == "completed":
                return parse_completed_analysis(domain, analysis_id, attributes)
            if status not in {"queued", "in-progress"}:
                raise VirusTotalError(f"Analysis {analysis_id} has unexpected status: {status!r}")
            if time.monotonic() >= deadline:
                raise VirusTotalError(f"Analysis {analysis_id} did not complete within the configured timeout")
            LOG.info("Analysis for %s is %s; polling again in %.0f seconds", domain, status, self.config.poll_interval_seconds)
            self.sleep(self.config.poll_interval_seconds)


def parse_completed_analysis(domain: str, analysis_id: str, attributes: Mapping[str, Any]) -> ScanResult:
    raw_stats = attributes.get("stats")
    raw_results = attributes.get("results")
    if not isinstance(raw_stats, Mapping) or not isinstance(raw_results, Mapping):
        raise VirusTotalError("Completed analysis is missing stats or results")

    stats: dict[str, int] = {}
    for key, value in raw_stats.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise VirusTotalError(f"Invalid analysis statistic {key!r}: {value!r}")
        stats[str(key)] = value

    findings: list[Finding] = []
    for engine_key, raw_result in raw_results.items():
        if not isinstance(raw_result, Mapping):
            continue
        category = str(raw_result.get("category", "unknown"))
        if category not in {"malicious", "suspicious"}:
            continue
        findings.append(
            Finding(
                engine=str(raw_result.get("engine_name") or engine_key),
                category=category,
                result=str(raw_result.get("result") or "unspecified"),
            )
        )
    findings.sort(key=lambda item: (item.category, item.engine.lower()))
    return ScanResult(domain, analysis_id, stats, tuple(findings))


def parse_analysis_payload(payload: Mapping[str, Any]) -> ScanResult:
    """Parse a saved GET /analyses/{id} response for offline alert testing."""
    try:
        data = payload["data"]
        analysis_id = str(data["id"])
        attributes = data["attributes"]
        status = attributes["status"]
    except (KeyError, TypeError) as exc:
        raise VirusTotalError("Analysis JSON is missing data.id or data.attributes.status") from exc
    if status != "completed":
        raise VirusTotalError(f"Analysis JSON must have status 'completed', got {status!r}")

    raw_domain: Any = None
    meta = payload.get("meta")
    if isinstance(meta, Mapping):
        netloc_info = meta.get("netloc_info")
        if isinstance(netloc_info, Mapping):
            raw_domain = netloc_info.get("id")
    if not raw_domain:
        links = data.get("links") if isinstance(data, Mapping) else None
        item_url = links.get("item") if isinstance(links, Mapping) else None
        if isinstance(item_url, str):
            parsed = urllib.parse.urlparse(item_url)
            if parsed.path.startswith("/api/v3/domains/"):
                raw_domain = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
    if not isinstance(raw_domain, str) or not raw_domain.strip():
        raise VirusTotalError("Could not determine the domain from meta.netloc_info.id or data.links.item")
    try:
        domain = normalize_domain(raw_domain)
    except ConfigurationError as exc:
        raise VirusTotalError(str(exc)) from exc
    return parse_completed_analysis(domain, analysis_id, attributes)


def load_analysis_file(path: Path) -> ScanResult:
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            payload = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise VirusTotalError(f"Could not read analysis JSON {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise VirusTotalError("Analysis JSON root must be an object")
    return parse_analysis_payload(payload)


def format_alert(result: ScanResult) -> str:
    lines = [
        f"VirusTotal alert for {result.domain}",
        "",
        f"Malicious detections: {result.stats.get('malicious', 0)}",
        f"Suspicious detections: {result.stats.get('suspicious', 0)}",
        f"Analysis ID: {result.analysis_id}",
        "",
        "Flagging engines:",
    ]
    if result.findings:
        lines.extend(f"- {item.engine}: {item.category} ({item.result})" for item in result.findings)
    else:
        lines.append("- The aggregate stats are non-zero, but no matching engine details were returned.")
    return "\n".join(lines)


def append_alert(path: Path, result: ScanResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": result.domain,
        "analysis_id": result.analysis_id,
        "stats": result.stats,
        "findings": [item.__dict__ for item in result.findings],
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")


def send_alert(config: Config, result: ScanResult) -> None:
    message = EmailMessage()
    message["Subject"] = f"[VirusTotal] {result.domain} has malicious/suspicious detections"
    message["From"] = config.smtp_from
    message["To"] = ", ".join(config.smtp_recipients)
    message.set_content(format_alert(result))

    LOG.info("Sending mail...")

    smtp_class = smtplib.SMTP_SSL if config.smtp_security == "ssl" else smtplib.SMTP
    kwargs: dict[str, Any] = {"timeout": config.http_timeout_seconds}
    if config.smtp_security == "ssl":
        kwargs["context"] = ssl.create_default_context()
    with smtp_class(config.smtp_host, config.smtp_port, **kwargs) as client:
        if config.smtp_security == "starttls":
            client.ehlo()
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if config.smtp_username and config.smtp_password:
            client.login(config.smtp_username, config.smtp_password)
        client.send_message(message)


def handle_result(config: Config, result: ScanResult) -> None:
    if result.is_flagged:
        alert = format_alert(result)
        print(alert, flush=True)
        append_alert(config.alert_log, result)
        send_alert(config, result)
        LOG.warning("Alert logged and emailed for %s", result.domain)
    else:
        LOG.info("No malicious or suspicious detections for %s", result.domain)


def run(config: Config) -> int:
    client = VirusTotalClient(config)
    had_errors = False
    last_submission_at: float | None = None
    for domain in config.domains:
        if last_submission_at is not None:
            remaining = config.domain_delay_seconds - (time.monotonic() - last_submission_at)
            if remaining > 0:
                LOG.info("Waiting %.0f seconds before submitting the next domain", remaining)
                time.sleep(remaining)
        try:
            LOG.info("Submitting VirusTotal scan for %s", domain)
            # Record the attempt before I/O as well as after success. This keeps
            # the next domain spaced out even when the response is lost.
            last_submission_at = time.monotonic()
            analysis_id = client.submit_domain(domain)
            last_submission_at = time.monotonic()
            result = client.wait_for_analysis(domain, analysis_id)
            handle_result(config, result)
        except (VirusTotalError, OSError, smtplib.SMTPException) as exc:
            had_errors = True
            LOG.error("Failed to process %s: %s", domain, exc)
    return 1 if had_errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true", help="validate configuration without sending requests")
    parser.add_argument(
        "--analysis-json",
        type=Path,
        metavar="PATH",
        help="process a saved completed analysis response instead of contacting VirusTotal",
    )
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        config = load_config(require_virustotal=args.analysis_json is None)
    except ConfigurationError as exc:
        LOG.error("Configuration error: %s", exc)
        return 2
    if args.check_config:
        if args.analysis_json:
            try:
                result = load_analysis_file(args.analysis_json)
            except VirusTotalError as exc:
                LOG.error("Analysis JSON error: %s", exc)
                return 2
            LOG.info("Configuration and analysis JSON are valid for %s", result.domain)
        else:
            LOG.info("Configuration is valid for %d domain(s)", len(config.domains))
        return 0
    if args.analysis_json:
        try:
            handle_result(config, load_analysis_file(args.analysis_json))
        except (VirusTotalError, OSError, smtplib.SMTPException) as exc:
            LOG.error("Failed to process analysis JSON: %s", exc)
            return 1
        return 0
    return run(config)


if __name__ == "__main__":
    sys.exit(main())
