# VirusTotal domain monitor

This Python 3 utility requests a fresh [VirusTotal](https://www.virustotal.com/) scan for every configured domain, polls the returned analysis ID until completion, and checks the `malicious` and `suspicious` counters. A flagged domain is printed, appended to a JSON Lines alert log, and sent to the configured SMTP recipients with each flagging engine's `result`.

It uses only the Python standard library. Python 3.10 or newer is recommended.

## Configure

Copy `.env.example` to a protected environment file and replace every example value. The script reads the process environment directly; it deliberately does not parse `.env` files or require a package for doing so.

Required variables:

| Variable | Meaning |
| --- | --- |
| `VT_API_KEY` | [VirusTotal API v3](https://docs.virustotal.com/reference/overview) key; sent only in the `x-apikey` header |
| `VT_DOMAINS` | Comma-separated domain names, without schemes or paths |
| `SMTP_HOST` | SMTP server |
| `SMTP_FROM` | Alert sender address |
| `SMTP_RECIPIENTS` | Comma-separated recipient addresses |

SMTP authentication is optional, but `SMTP_USERNAME` and `SMTP_PASSWORD` must be provided together. `SMTP_SECURITY` accepts `starttls` (default), `ssl`, or `none`. See `.env.example` for all timeouts and defaults.

The program refuses `VT_DOMAIN_DELAY_SECONDS` values below 60. The delay is measured between submission times, so polling a slow analysis does not add an unnecessary extra minute. It also honors HTTP `429 Retry-After` responses and retries temporary HTTP/server/network failures.

Validate the environment without contacting VirusTotal or SMTP:

```bash
set -a
. /etc/vt-domain-monitor.env
set +a
python3 vt_domain_monitor.py --check-config
```

Run one scan cycle:

```bash
python3 vt_domain_monitor.py
```

### Test with a saved analysis response

Use `--analysis-json` to process a saved, completed `GET /analyses/{id}` response without sending any requests to VirusTotal:

```bash
python3 vt_domain_monitor.py --analysis-json virus-total-api-get-analysis-result.json
```

In this mode, `VT_API_KEY` and `VT_DOMAINS` are not required. SMTP configuration is still required because a malicious or suspicious fixture follows the normal alert path: it is printed, written to `VT_ALERT_LOG`, and emailed. The domain is read from `meta.netloc_info.id`, with `data.links.item` as a fallback.

To validate both the environment and JSON structure without writing a log or sending email:

```bash
python3 vt_domain_monitor.py --analysis-json virus-total-api-get-analysis-result.json --check-config
```

Exit status is `0` when every domain is processed, `1` when one or more domains fail, and `2` for invalid configuration. A detection itself is not treated as an execution failure.

## Run with Docker

Build the image from the repository root:

```bash
docker build -t vt-domain-monitor:1.0.0 .
```

Or use the available image from the container registry of this repo: `satrd-iot/vt-domain-monitor:dev`

Validate the configuration. The explicit `VT_ALERT_LOG` override keeps container output under the mounted `/data` directory instead of using the host-oriented path from `.env`:

```bash
mkdir -p logs
docker run --rm \
  --env-file .env \
  --env VT_ALERT_LOG=/data/alerts.jsonl \
  --volume "$(pwd)/logs:/data" \
  vt-domain-monitor:1.0.0 --check-config
```

Run a real scan by removing `--check-config`:

```bash
docker run --rm \
  --env-file .env \
  --env VT_ALERT_LOG=/data/alerts.jsonl \
  --volume "$(pwd)/logs:/data" \
  vt-domain-monitor:1.0.0
```

The image runs as the unprivileged UID/GID `10001`. Ensure the mounted log directory is writable by that identity. On Linux, this can be done with `sudo chown -R 10001:10001 logs`. The build context excludes `.env`, saved analysis results, logs, and development files so credentials and fixtures are not copied into the image.

To test a saved response in Docker, mount it read-only:

```bash
docker run --rm \
  --env-file .env \
  --env VT_ALERT_LOG=/data/alerts.jsonl \
  --volume "$(pwd)/logs:/data" \
  --volume "$(pwd)/analysis-results.json:/fixtures/analysis-results.json:ro" \
  vt-domain-monitor:1.0.0 --analysis-json /fixtures/analysis-results.json
```

## Run daily in Kubernetes

The manifests in `k8s/` provide a ConfigMap, a Secret input template, a persistent volume claim for JSONL alerts, and a hardened daily CronJob. The example schedule is `02:17` in `Europe/Madrid`. Kubernetes supports `.spec.timeZone` from version 1.27; remove that field on older clusters and interpret the schedule in the controller manager's time zone.

1. Build the container, push it to a registry available to the cluster, and replace the example image in `k8s/cronjob.yaml`:

   ```bash
   docker build -t registry.example.org/security/vt-domain-monitor:1.0.0 .
   docker push registry.example.org/security/vt-domain-monitor:1.0.0
   sed -i 's|ghcr.io/your-org/vt-domain-monitor:1.0.0|registry.example.org/security/vt-domain-monitor:1.0.0|' k8s/cronjob.yaml
   ```

  Or use the available image from the container registry of this repo: `satrd-iot/vt-domain-monitor:dev`

2. Edit the non-secret values in `k8s/configmap.yaml`. Use port `587` with `starttls`, or port `465` with `ssl`.

3. Create the Kubernetes Secret without committing real credentials:

   ```bash
   cp k8s/secrets.env.example k8s/secrets.env
   chmod 600 k8s/secrets.env
   # Edit k8s/secrets.env, then create or replace the Secret:
   kubectl create secret generic vt-domain-monitor-secrets \
     --from-env-file=k8s/secrets.env \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

4. Apply the resources:

   ```bash
   kubectl apply -f k8s/configmap.yaml
   kubectl apply -f k8s/pvc.yaml
   kubectl apply -f k8s/cronjob.yaml
   ```

5. Start a one-off Job and inspect it before waiting for the daily schedule:

   ```bash
   kubectl create job --from=cronjob/vt-domain-monitor vt-domain-monitor-manual
   kubectl logs -f job/vt-domain-monitor-manual
   kubectl get cronjob vt-domain-monitor
   ```

`concurrencyPolicy: Forbid` prevents overlapping runs. The PVC preserves `/data/alerts.jsonl` between Jobs; it requires a default StorageClass. If the registry is private, configure an `imagePullSecret` in the Pod template. Kubernetes Secrets are not encrypted in etcd by default unless the cluster is configured for encryption at rest.

## Run daily with systemd

The files under `systemd/` are production-oriented examples for Linux/Proxmox. They assume:

- the project is installed at `/opt/vt-domain-monitor`;
- configuration is stored at `/etc/vt-domain-monitor.env` with mode `0600`;
- an unprivileged `vt-monitor` user/group exists; and
- `VT_ALERT_LOG=/var/log/vt-domain-monitor/alerts.jsonl`, with that directory writable by `vt-monitor`.

Install and activate the units as root:

```bash
cp systemd/vt-domain-monitor.service systemd/vt-domain-monitor.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vt-domain-monitor.timer
systemctl list-timers vt-domain-monitor.timer
```

For a quick cron alternative, load the protected environment and run once daily:

```cron
17 2 * * * set -a; . /etc/vt-domain-monitor.env; set +a; /usr/bin/python3 /opt/vt-domain-monitor/vt_domain_monitor.py
```

Do not put secrets directly in the crontab or commit the real environment file.

## Test

The tests use mocks and never contact VirusTotal or an SMTP server:

```bash
python3 -m unittest discover -s tests -v
```

## API behavior

The implementation uses [VirusTotal API v3](https://docs.virustotal.com/reference/overview)'s domain rescan endpoint (`POST /domains/{id}/analyse`) and analysis endpoint (`GET /analyses/{id}`). It waits for `status=completed` before evaluating `stats` and `results`.
