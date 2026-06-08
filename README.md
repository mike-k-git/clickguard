# Clickguard

[![CI](https://github.com/mike-k-git/clickguard/actions/workflows/ci.yml/badge.svg)](https://github.com/mike-k-git/clickguard/actions/workflows/ci.yml)

Clickguard surfaces bot traffic and click fraud signals in web and ad-server access logs. It reads Common Log Format (CLF) input, runs a set of detectors over the parsed events, and scores each actor by the rules they triggered. The result is a ranked list of suspect IPs with band assignments (clear / suspect / fraud) and rule breakdowns.

It is a portfolio project with a real fraud-mitigation domain. The scoring model is intentionally simple at this stage — the goal is behavioral signal surfacing, not a production-grade verdict engine.

## Build

Requires Elixir 1.20+.

```bash
mix deps.get
mix escript.build
```

This produces a `./clickguard` escript.

## Usage

```bash
# file path
./clickguard access.log

# stdin
cat access.log | ./clickguard

# options
./clickguard access.log --format json
./clickguard access.log --fail-on suspect
```

### Options

`--format text|json` — output format. Defaults to `text`.

`--fail-on suspect|fraud` — exit with code 2 if any actor bands at or above the given level. `suspect` is triggered by suspect and fraud; `fraud` by fraud only. Without this flag the exit code reflects only whether the run succeeded.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Ran successfully; `--fail-on` threshold not met or not set. |
| 1 | Error; bad arguments, unknown flag, unreadable input. |
| 2 | `--fail-on` threshold met. |

Code 2 is separate from code 1 so a CI step can distinguish a clean log from a broken invocation.

## Output

### Text (default)

Tab-separated table, sorted fraud → suspect → clear, then by score descending within band.

```
actor           events  band    score   summary worst
ip:127.0.0.1    303     fraud   4       low: 4  :high_frequency_ip (300)
ip:10.0.0.10    4       suspect 2       low: 3  :automation_tool (2)
ip:10.0.0.1     1       clear   1       low: 1  :automation_tool (1)
ip:10.0.0.2     1       clear   1       low: 1  :automation_tool (1)
ip:192.168.1.1  1       clear   1       low: 1  :spam_referer (1)
ip:192.168.1.10 2       clear   1       low: 2  :spam_referer (1)
ip:192.168.1.2  1       clear   1       low: 1  :spam_referer (1)
```

### JSON

```bash
./clickguard test/fixtures/fraud.log --format json | jq
```

```json
[
  {
    "band": "fraud",
    "score": 4,
    "actor": {
      "type": "ip",
      "value": "127.0.0.1"
    },
    "total_events": 303,
    "total_findings": 4,
    "rules": {
      "headless_browser": {
        "event_count": 1,
        "severity": "low"
      },
      "automation_tool": {
        "event_count": 1,
        "severity": "low"
      },
      "high_frequency_ip": {
        "event_count": 300,
        "severity": "low"
      },
      "spam_referer": {
        "event_count": 1,
        "severity": "low"
      }
    }
  },
  ...
]
```

## Detectors

Each detector is an independent stage. Findings are per `{IP, rule}` pair. One actor triggering the same rule N times produces one finding, not N.

**FreqIp** flags IPs exceeding 300 requests per 60-second sliding window. Returns the first offending window, not the peak.

**UserAgent** flags requests from known automation tools (`python-requests`, `curl`, `wget`, `go-http-client`, `scrapy`) and headless browsers (`HeadlessChrome`, `PhantomJS`), and nil/blank UAs. Catches lazy bots only. Real-UA spoofing is out of scope.

**Referer** flags nil/blank referers and requests from known referer-spam domains. Host matching is exact (normalized: lowercase, `www.` stripped). The spam domain list is configurable.

## Scoring

The scorer aggregates findings per actor and assigns a band.

Rule weights: low = 1, medium = 3, high = 16. Hygiene-only rules (`:empty_ua`, `:empty_referer`) carry weight 0 and do not affect banding on their own.

Bands are assigned on rule diversity, not event volume: one medium rule → suspect; medium + any low → fraud; four distinct lows → fraud; any high → fraud.

| Band | Score |
|------|-------|
| clear | ≤ 1 |
| suspect | ≤ 3 |
| fraud | > 3 |

## Architecture

The pipeline is `parse → detect → score`. Detectors run concurrently via `Task.async_stream`. The scorer joins findings per actor and produces one `Score` per actor. Reporters (`Text`, `JSON`) are implementations of the `Reporter` behaviour and consume the score list.
