# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Splunk **modular input** app that polls Cloudflare's Enterprise Log Share (ELS) API and streams request logs into Splunk for indexing. It was forked from Splunk's generic "REST API Modular Input" (Splunkbase app 1546) and stripped down to the single Cloudflare use case.

All runtime logic lives in `bin/cloudflare.py`. The rest of the repo is Splunk packaging: `default/` (app config, modular-input UI), `metadata/`, `README/` (input spec), and `appserver/static/` (icon/screenshots).

## Critical constraints

- **Python 2.7 only.** The code uses Python 2 syntax that will not parse under Python 3: `print` statements, `except SomeError, e:`, `raise Exception, "msg"`. Splunk ships its own Python 2.7 interpreter and runs this script with it. Do not "modernize" to Python 3 unless explicitly asked — it would break the running app.
- **The app directory must be named `cloudflare`.** `bin/cloudflare.py` hardcodes `EGG_DIR = SPLUNK_HOME + "/etc/apps/cloudflare/bin/"` to locate its dependencies. Installation instructions clone the repo to `$SPLUNK_HOME/etc/apps/cloudflare` for this reason.
- **Dependencies are vendored as eggs**, not pip-installed: `bin/requests-2.0.0-py2.7.egg` and `bin/splunk_sdk-1.0.0-py2.7.egg`. At startup the script scans `EGG_DIR` and appends every `.egg` to `sys.path` before importing `requests` and `splunklib`.

## How the modular input works

Splunk invokes `bin/cloudflare.py` in one of three modes (see the `__main__` block):

- `--scheme` → prints the `SCHEME` XML describing input arguments (shown in Splunk's UI).
- `--validate-arguments` → validation hook (currently a near no-op).
- no args → run mode. Reads its stanza config as XML from **stdin** (`get_input_config`), then enters `do_run`.

`do_run` is the main loop:
1. Resolves `zone_name` → Cloudflare `zone_tag` by calling `GET /client/v4/zones`. Exits if the zone isn't found.
2. Polls `GET /client/v4/zones/{zone_tag}/logs/requests` as a **streaming** request, iterating line-by-line.
3. Each line is passed to `CloudFlareEventHandler.__call__`, which parses the JSON and `print`s it to stdout — that stdout is what Splunk indexes.
4. Tracks `last_ray_id` so the next poll resumes after the last fetched event; on error/timeout it sleeps `backoff_time` and retries; between successful polls it sleeps `polling_interval`.

**State persistence:** `update_rayid` writes the latest `start_id` back into the input's stanza via the Splunk SDK (`splunklib.client.Service`), so progress survives restarts. Note it uses `SESSION_TOKEN`/`SPLUNK_PORT` derived from the config — `SPLUNK_PORT = server_uri[18:]` and `STANZA[13:]` (stripping the `cloudflare://` prefix) are brittle string slices that assume specific formats.

## Input arguments

Defined in both `bin/cloudflare.py` (`SCHEME`), `README/inputs.conf.spec`, and `default/data/ui/manager/rest_manager.xml` — **keep these three in sync** when adding or renaming an argument. Args: `zone_name`, `auth_email`, `auth_key` (required), plus optional `last_ray_id`, `request_timeout` (default 30), `backoff_time` (default 10), `polling_interval` (default 60, accepts cron syntax per the UI help text).

## Setup / running

There is **no build, test, or lint tooling** in this repo. It is deployed by copying into a Splunk install:

1. Clone to `$SPLUNK_HOME/etc/apps/cloudflare`.
2. Define an `ELS` sourcetype (props.conf snippet is in `README.md` — JSON indexed extraction, epoch-nanosecond timestamps from the `timestamp` field, UTC).
3. Create a "CloudFlare Log Share" data input via Manager → Data Inputs, set its sourcetype to `ELS`.
4. Restart Splunk. Errors are logged to `$SPLUNK_HOME/var/log/splunk/splunkd.log`.

To smoke-test the scheme without a full Splunk run: `$SPLUNK_HOME/bin/splunk cmd python bin/cloudflare.py --scheme`.

## Stale upstream docs — do not trust

`appserver/static/README.md` and `appserver/static/RELEASE_NOTES.md` are leftovers from the upstream generic REST modular input. They describe features that **do not exist in this fork**: OAuth, custom auth/response handlers, `tokens.py` / `authhandlers.py` / `responsehandlers.py`, a `rest_ta/bin/` directory, token substitution, etc. None of those files or capabilities are present here. Treat the top-level `README.md` as the authoritative doc for this app.
