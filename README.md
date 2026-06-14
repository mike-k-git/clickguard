# Clickguard

[![CI](https://github.com/mike-k-git/clickguard/actions/workflows/ci.yml/badge.svg)](https://github.com/mike-k-git/clickguard/actions/workflows/ci.yml)

Clickguard surfaces bot traffic and click fraud signals in web access logs. It reads Common Log Format (CLF) input, runs a set of detectors over the parsed events, and scores each actor (IP or session) by the rules they triggered. The result is a ranked list with band assignments (clear/suspect/fraud) and rule breakdowns.

It is a portfolio project with a real fraud-mitigation domain. The scoring model is intentionally simple at this stage. The goal is behavioral signal surfacing, not a production-grade verdict engine.

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

`--format text|json` output format. Defaults to `text`.

`--fail-on suspect|fraud` exit with code 2 if any actor bands at or above the given level. `suspect` is triggered by suspect and fraud; `fraud` by fraud only. Without this flag the exit code reflects only whether the run succeeded.

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
actor                                       events  band    score   summary           worst
session:172.16.0.1|high-velocity-browser    25      fraud   32      high: 1           :click_velocity (25)
session:172.16.0.4|burst-then-idle-browser  32      fraud   16      high: 1           :click_velocity (6)
session:172.16.0.3|medium-cadence-browser   25      fraud   6       medium: 1         :click_velocity (25)
ip:127.0.0.1                                303     suspect 5       low: 4            :high_frequency_ip (300)
session:172.16.0.2|medium-cadence-browser   8       suspect 3       medium: 1         :click_velocity (8)
ip:10.0.0.10                                4       suspect 2       low: 2, info: 1   :automation_tool (2)
ip:10.0.0.1                                 1       clear   1       low: 1            :automation_tool (1)
ip:10.0.0.2                                 1       clear   1       low: 1            :automation_tool (1)
ip:192.168.1.1                              1       clear   1       low: 1            :spam_referer (1)
ip:192.168.1.10                             2       clear   1       low: 1, info: 1   :spam_referer (1)
ip:192.168.1.2                              1       clear   1       low: 1            :spam_referer (1)
```

### JSON

```bash
./clickguard test/fixtures/fraud.log --format json | jq
```

```json
[
  {
    "band": "fraud",
    "score": 16,
    "actor": {
      "type": "session",
      "value": "172.16.0.4|burst-then-idle-browser"
    },
    "total_events": 32,
    "total_findings": 1,
    "rules": {
      "click_velocity": {
        "event_count": 6,
        "severity": "high"
      }
    }
  },
  ...
]
```

### Malformed lines

If there are malformed lines, clickguard prints a warning to stderr. Empty lines are skipped completely.

```bash
clickguard: parsed N/M lines (K rejected)
```

## Detectors

Each detector is an independent stage. Findings are per `{actor, rule}` pair. One actor triggering the same rule N times produces one finding, not N.

**FreqIp** flags IPs exceeding 300 requests per 60-second sliding window. Returns the first offending window, not the peak. The peak window is recorded in evidence.

**UserAgent** flags requests from known automation tools (`python-requests`, `curl`, `wget`, `go-http-client`, `scrapy`) and headless browsers (`HeadlessChrome`, `PhantomJS`), and nil/blank UAs. Catches lazy bots only. Real-UA spoofing is out of scope.

**Referer** flags nil/blank referers and requests from known referer-spam domains. Host matching is exact (normalized: lowercase, `www.` stripped). The spam domain list is configurable.

**ClickVelocity** flags `{ip, ua}` pairs whose click cadence is robotic. Events are grouped into sessions split on a 30-minute idle gap. A session of 5+ clicks fires on its median inter-click interval: <=2s is `:medium`, <=1s is `:high`; or on 5+ clicks inside one second (`:high`). It is the first detector to emit severities above `:low`. Calibrated for click-granular logs; threshold recalibration needed on raw access logs serving mixed content.

## Scoring

The scorer aggregates findings per actor and assigns a band.

Rule weights: info = 0 (hygiene-only rules), low = 1, medium = 3, high = 16.

Bands are assigned on rule diversity, not event volume: one medium rule → suspect; medium + any low → fraud; any high → fraud.

### Score Boost

When a rule accounts for >= 50% of an actor's total traffic and the actor has >= 20 events, its weight is doubled. This approach prioritizes consistent patterns over random detections: a session that is robotic throughout its entire duration yields more signal than one with an isolated burst.

### Band Cap

An actor whose findings are all `:low` severity does not exceed `:suspect` level, regardless of score.
Fraud requires at least one `:medium` or `:high` finding (behavioral evidence, not just
accumulated hygiene markers).

### Band Table

| Band | Score | Notes |
|------|---------|-----|
| clear | <= 1 | - |
| suspect | <= 3 | - |
| fraud | > 3 | needs at least one :medium or :high finding |

## Roadmap

**v0.3 – streaming pipeline.** The current architecture materialises the full event list before detection. The next logical step is a Flow/GenStage refactor: a true streaming pipeline where events flow through partitioned stages. The scorer (stateful reduce) and ClickVelocity (stateful session stage) already define the partition shape.

**v0.4 – ad-log parser.** CLF can identify robotic traffic, but not click fraud, as this is an economic event and requires source, campaign, conversion, and cost data. A pluggable ad-log parser would enrich `Event` with these fields and activate a dormant detector family: conversion outlier detection, geographic concentration, and source-keyed scoring. This is the step that earns the "ad fraud" framing.

**Detector improvements.** UA-rotation detection (many distinct UAs from one IP are a real indicator of datacenter proxy bots, but needs volume-relative counting to avoid false positives on NAT egress). Crawler-spoof detection (claims crawler UA but IP not in a verified range). Publisher-referer mismatch. All are blocked on config or enrichment that v0.4 introduces.

## How it works

The architecture treats the scorer as the product. Detectors are independent feature extractors, each one producing findings rather than a final verdict. The scorer module aggregates these findings for each actor, applies weights, and produces the final band. This functional division is intentional: any single rule is only a weak indicator, while the actual judgment is made by the scorer. Consequently, adding a detector does not change the scorer; new detectors simply widen the evidence pool without affecting the weighting logic.

The findings are associated with actors, where an actor is an `{actor_type, subject}` pair. Version 0.2 defines two types. The `:ip` type carries per-IP findings from FreqIp, UserAgent, and Referer, while the `:session` type covers `{ip, ua}` pairs identified by ClickVelocity. The event denominator belongs to `actor_totals/1` alone. Introducing a third actor type only requires this single function to be extended, rather than sweeping changes to be made across the entire system.

The evidence contract ensures that the layers remain clean. Each finding carries a detector-typed `evidence` map rich enough that the scorer never has to re-read the event stream. If the scorer does require access to the raw events, this indicates a violation of the abstraction principle and signals that the system requires refinement.

When it comes to concurrency, it's important to be precise about what is actually happening. Detectors run concurrently via `Task.async_stream` over a materialised event list, which is a form of concurrent batch dispatch rather than a true streaming pipeline. A streaming refactor using Flow/GenStage is planned for a future version.

All of this is based on one input assumption. Both FreqIp and ClickVelocity are calibrated for click-granular logs. If you point them at raw server logs full of mixed asset requests, the thresholds will no longer hold. The v0.4 ad-log parser addresses this issue directly by filtering by request type, so only the relevant events reach the appropriate detectors.

Taken together, the design centralizes all interpretation and maintains everything upstream as dumb, composable extraction. Detectors observe and report, and the scorer decides. This separation is the key concept, and most of the roadmap is about extending the inputs without disturbing it.
