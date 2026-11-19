# Data handling

Tool arguments and results can hold secrets: the code `scan_secrets` scans, a token
pasted into a search, an incident's matched value. This page says where such data goes
and what keeps it out of everywhere else. One module,
[`gg_api_core/sanitization.py`](src/gg_api_core/sanitization.py), holds the rules that
logs, traces and error messages share.

## What goes where

| Channel | What it carries | What keeps sensitive data out |
|---|---|---|
| GitGuardian API | Each tool's arguments, in the request that needs them. Your token, as the `Authorization` header. | Nothing else is sent anywhere. |
| Tool results, read by the model | What the API returns. | Every API request asks for privacy mode (`X-Privacy-Mode: true`), which masks secret values in incidents and occurrences. The one exception is the honeytoken calls: `generate_honeytoken` returns the decoy credential, because planting it is what the tool is for. |
| Error messages, read by the model | Why a call failed, and what to do next. | An argument error names the field, never the value. A failed assignment by email does not repeat the address. |
| Logs | One event per tool call: tool name, outcome, durations, result size, and the request, session, workspace, member and token IDs. | No argument values and no results are logged. Every field passes through the shared scrubbing: values under sensitive names (`token`, `secret`, `password`, `document`, `content`, `match` and others) are redacted, URLs keep their path only, credentials in Git URLs are removed, and the inputs that validation errors quote are replaced. HTTP client request logs stay below INFO. |
| Error tracking (Sentry, when `SENTRY_DSN` is set) | Unexpected failures, and spans for tool calls. | No local variables, no request bodies, no default PII. Tool argument values are dropped from spans, and every string goes through the same scrubbing as the logs. |

## Rules for new code

- Send an argument only to the endpoint that needs it, and keep privacy mode on unless the
  tool exists to return a credential.
- Log identifiers and sizes, never argument values or results. If a field name carries a
  value that must not be logged, add it to `SENSITIVE_PARAMETER_NAMES`.
- Never put an argument's value in an error message: name the argument instead.
- Add a test with the new path to `tests/test_sanitization.py` or
  `tests/test_sentry_integration.py`.
