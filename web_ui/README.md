# TRACE web UI

Visual SSH investigation with six stages: Onboard, Plan, Investigate, Challenge, Verify and Brief. Includes recorded playback, live execution, animated tool receipts and claim verification, stage colours, an evidence drawer and a full C2/C3 report library.

## Run recorded mode

Requires Python 3.11 or newer. No installation, Docker, API key or frontend build is needed.

From the repository root:

```bash
git switch webui
python3 -m web_ui.server
```

Open **http://127.0.0.1:8767/**.

- **Play case** replays the verified SSH investigation at 1×, 4× or 8× speed.
- Select a stage to inspect it directly, or use Back / Next.
- **Inspect evidence** opens claims, original event references, raw input, tool receipts and review notes.
- **Reports & logs** opens the full C2/C3 reports and run logs. Download individual files or the complete ZIP; the text-brief export has been removed.
- **Pause motion** stops the illustration. Reduced-motion preferences are respected.
- **Run details** shows execution metadata.

To use another port:

```bash
python3 -m web_ui.server --port 8768
```

Keep the server running while using the page. Press Ctrl+C in its terminal to stop it. Open the HTTP URL rather than opening `index.html` directly: the page uses local API routes.

## Run the real pipeline

Live mode runs the existing fixed SSH integration: isolated services → B3 onboarding → A3/A2 transport → Elasticsearch parsing → C1/C2 hunt → C3 verification → report → cleanup. It uses the current committed code, not uncommitted backend edits. It requires Linux UID 1000 (the integration harness's container ownership assumption), Docker access, OpenSSL, Git and the two Python environments below. Allow roughly 3 GiB for the two capped containers plus Python and Docker overhead.

Set up the dependencies once from the repository root:

```bash
python3.11 -m venv group_B/.venv
group_B/.venv/bin/python -m pip install -r group_B/requirements.txt

python3.11 -m venv web_ui/runtime/hunt-venv
web_ui/runtime/hunt-venv/bin/python -m pip install \
  -r group_C/threat_hunting/requirements.txt \
  -r group_C/threat_hunting/evidence/requirements.txt

docker pull docker.elastic.co/elasticsearch/elasticsearch:8.19.23
docker pull docker.elastic.co/logstash/logstash:8.19.23
```

Reuse existing compatible environments if already configured. Group B and Group C use separate environments because their dependency pins differ. Pass the virtual environment's Python path without resolving its symlink to the base interpreter.

Create a private provider file outside version control containing:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.deepseek.com
LLM_API_KEY=<your-key>
HUNT_MODEL=deepseek-flash
```

Restrict its permissions, then start the server:

```bash
chmod 600 /absolute/path/to/private-provider.env
group_B/.venv/bin/python -m web_ui.server \
  --enable-live \
  --provider-env /absolute/path/to/private-provider.env \
  --hunt-python "$PWD/web_ui/runtime/hunt-venv/bin/python"
```

Open **http://127.0.0.1:8767/** and choose **Live → Run live investigation**. Normal provider charges apply only when starting a live investigation. Opening the UI, inspecting evidence and recorded playback do not call the provider. Live execution is disabled unless explicitly enabled at startup.

The existing harness caps model calls at eight per hunt and investigator steps at two. This UI uses one fixed synthetic scenario and an explicit one-hour UTC window that includes the successful login. It does not support arbitrary uploads or free-form hunts. **Stop run** cancels the investigation and invokes cleanup of owned test resources. UI stage navigation is locked during live execution.

Run artifacts and logs stay under ignored `web_ui/runtime/`. Credentials remain server-side. The loopback-only server checks Host/Origin and a session token for execution requests, and serves only allowlisted files. It is a local demo server, not a hosted multi-user service.

## Evidence and animation

`data/recorded-run.json` contains curated evidence from the actual DeepSeek run on merged commit `e2f249b`: 128.475 seconds, 35 indexed records, 31 cited attack events, four verified claims and 26 identical query replays. The raw development run is not included. All recorded data is synthetic.

Scene boundaries use measured phase durations. Moving packets and receipt rows illustrate the workflow; they do not represent exact request timing or private model reasoning. Live tool receipts are read as C2 writes its audit, with request/response payloads excluded. Live results never fall back to the recording.

LLM-origin findings remain leads, not vetted support. The retained C3 narrative annotation about `AG-02` is visible in the evidence drawer. Results require analyst review; the UI takes no autonomous response actions.

## Checks

```bash
python3 -m unittest discover -s web_ui/tests -v
python3 -m py_compile web_ui/server.py web_ui/runner.py web_ui/recording.py
```

To test the adapter against real local services without paid model calls, after setting up the environments and images:

```bash
group_B/.venv/bin/python -m web_ui.runner \
  --job-dir "$PWD/web_ui/runtime/rules-check-$(date +%s)" \
  --hunt-python "$PWD/web_ui/runtime/hunt-venv/bin/python" \
  --rules
```

The job directory must be new. This runs the real transport, indexing, rules hunt and independent verification. It does not certify a fresh live LLM result or replace the broader regression suite in `group_B/DEMO_RUNBOOK.md`.

Fonts are self-hosted; licenses are in `assets/fonts/`.

## Full reports and logs

After updating, restart the Python UI server so it loads the new report routes. Open **Reports & logs** from the main screen or **Open full reports & logs** inside the evidence drawer.

- **C2**: full investigation result, plan, phase timings, response draft and generated detection files. The reader provides collapsible report sections and the complete source.
- **C3**: complete styled HTML report, Markdown and JSON versions, and the evidence bundle. HTML is sandboxed with scripts, forms and external requests blocked.
- **Logs**: complete tool trace, model audit (including retained prompts/responses), Elasticsearch MCP audit, analytics audit, run summary and any retained wall timing / runner console. JSONL entries can be searched and expanded; pagination limits visible entries, not the downloadable log.

**Download file** exports the selected full artifact. **Download all (.zip)** exports every currently available artifact plus an inventory. Both use the same credential-redacted contents shown in the reader. No text summary is substituted. Missing files are labelled “not produced”; running and failed investigations may have fewer artifacts. Refresh files to load newly written output. Runtime directories and arbitrary files are never exposed as a static directory.

The reader retains the selected run ID when loading and downloading. New website runs remember their ID in local browser storage so their reports remain reachable after a page reload while the runtime artifacts exist. Recorded mode uses its own retained artifacts and never fills gaps in a live run with recorded results.

Recorded artifacts are packaged in `data/recorded-reports.json` and `data/recorded-reports.zip`. They match the same successful fixed-window run as `data/recorded-run.json`; the bundle includes 18 retained files. Live artifacts are collected from that job’s `artifacts/` directory and its console log. Credentials are redacted by key, provider-key patterns and the server’s configured provider secret.

Report endpoints:

- `/api/recording/reports` and `/api/recording/reports.zip`
- `/api/runs/<run-id>/reports` and `/api/runs/<run-id>/reports.zip`
- `/api/recording/reports/c3-html/view` and `/api/runs/<run-id>/reports/c3-html/view`

For a future GitHub Pages update, the hosting adapter must also map `reports.js`, `reports.css`, the recorded bundle/ZIP routes and the sandboxed C3 HTML route to these packaged static artifacts. Pulling the source branch alone does not update a separate `gh-pages` deployment. This change does not update any fork or Pages site.
