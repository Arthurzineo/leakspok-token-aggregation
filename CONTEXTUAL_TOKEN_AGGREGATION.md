# Contextual token aggregation

## Motivation

Leakspok normally evaluates each tokenizer output independently. That fast path
works for values contained in one token, but formatted PII may be split into
several tokens. Examples include `+55 54 99912 0654`,
`5 5 5 4 9 9 9 1 2 0 6 5 4`, `529 982 247 25`, and
`test @ example . com`. Credit cards such as `5200 1000 0000 2803` are also
split by horizontal whitespace. None of the individual fragments is sufficient
for the corresponding matcher, even though the complete value is PII.

The new opt-in contextual path joins only adjacent, compatible fragments into a
canonical candidate, validates that candidate with the existing matchers, and
applies the selected anonymization strategy to the complete original byte span.
This preserves the established rule, exception, cache, masking, and redaction
semantics instead of introducing a second matching system.

## Design and safety bounds

- Disabled by default through `RunnerOptions.ContextualDetection.Enabled`.
- Limited initially to PHONE, CPF, CREDIT_CARD, and EMAIL rules.
- Numeric candidates accept only digits and an allowlisted set of formatting
  characters. They are bounded to 17 tokens, 64 bytes, and 16 digits.
- Email candidates use a small, allowlisted grammar and are bounded to 5 tokens
  and 254 bytes.
- Words, newlines, and unsupported separators stop aggregation.
- Findings retain offsets into the original input; formatting is never silently
  removed from the output.
- Overlapping findings are resolved deterministically. Their union is protected
  with the settings of the largest validated span so a chained overlap cannot
  leave matched bytes exposed.
- Candidate scanning is bounded and overlap resolution is `O(n log n)`.
- The existing bounded worker pool is reused in concurrent mode.
- Inputs without a possible contextual marker (ASCII digit for numeric entities
  or `@` for EMAIL) return to the legacy path before token materialization.

These constraints are important because unrestricted token concatenation could
create false positives, join unrelated data, or cause excessive CPU and memory
use on adversarial input.

## Bounded candidate examples

A candidate has two representations: canonical bytes sent to the existing
matcher and a byte span pointing to the complete value in the original input.
Only adjacent fragments connected by an allowlisted horizontal separator may be
combined.

| Original fragments | Canonical candidate | Entity | Result |
|---|---|---|---|
| `+55` `54` `99912` `0654` | `+5554999120654` | PHONE | accepted if the phone matcher validates it |
| `5` `5` `5` `4` `9` `9` `9` `1` `2` `0` `6` `5` `4` | `5554999120654` | PHONE | accepted; 13 digit tokens remain within the 17-token limit |
| `529` `982` `247` `25` | `52998224725` | CPF | accepted only when the CPF checksum is valid |
| `5200` `1000` `0000` `2803` | `5200100000002803` | CREDIT_CARD | accepted only for a supported prefix and valid Luhn checksum |
| `5` `2` `0` `0` `1` `0` `0` `0` `0` `0` `0` `0` `2` `8` `0` `3` | `5200100000002803` | CREDIT_CARD | accepted at the 16-digit bound |
| `test` `@` `example` `.` `com` | `test@example.com` | EMAIL | accepted; exactly the 5-token email limit |

For example, with `call +55 54 99912 0654 now`, the phone matcher receives
`+5554999120654`, but the action keeps the original span for
`+55 54 99912 0654`. Redaction therefore produces `call <PHONE> now` without
changing offsets based on the shorter canonical representation.

Examples that stop or are rejected:

- `+55 54\n99912 0654`: newline is not an allowed gap, so the complete value is
  not aggregated across the line boundary.
- `55 code 54 code 99912`: words between numeric fragments stop the numeric
  scanner.
- Numeric input beyond 16 digits, 17 tokens, or 64 bytes: the complete chain is
  rejected and no shorter prefix is emitted as a finding.
- `test @ unrelated words example . com`: the email grammar does not skip words
  to manufacture an address.
- Longer email-like input: the scanner never extends a candidate beyond 5
  tokens or 254 bytes, and it does not redact a bounded prefix when a connected
  suffix indicates that the address continues.

The limits control worst-case work per starting token. They do not make a
candidate a finding by themselves; the corresponding existing matcher must
still validate the canonical value.

## Documented false-positive trade-off

Contextual PHONE detection deliberately reuses the legacy `PhoneMatcher`, whose
regex accepts short phone-like digit sequences and is not anchored to a stricter
regional numbering plan. With the feature enabled, unrelated horizontal numeric
groups such as `Sala 101 202 303` may canonicalize to a value accepted as PHONE.
This is a known false-positive trade-off and a reason the feature remains
disabled by default.

Dates receive a cheap structural exclusion before PHONE evaluation. Supported
calendar layouts are Brazilian `DD-MM-YYYY`, United States `MM-DD-YYYY`, and ISO
`YYYY-MM-DD`, with `-`, `.`, or `/` separators. Optional valid times include
`HH`, `HHMM`, `HH:MM`, and `HH:MM:SS`. The check validates real month lengths
and leap years, so `29-02-2024` is excluded from PHONE while `31-02-2024` is not.
Ambiguous values such as `05-06-2024` are considered a date when either the BR
or US interpretation is valid.

ISO date-times using `T`/`t`, such as `2026-08-23T14:30:00`, optional fractional
seconds with one to nine digits and `Z` or numeric timezone offsets, and times
split into separate fields, such as `23-08-2026 14 30 45`, are also recognized.

The date check is a bounded byte parser, not a new regular expression or a
general natural-language date parser. Numeric candidates remain capped at 64
bytes. Raw tokens use a constant-time separator precheck and are scanned only
when date-shaped. Month names, two-digit years, time zones, and free-form dates
are intentionally outside its scope. A real phone deliberately formatted
exactly like a valid supported date will be excluded; this is the chosen
trade-off to avoid common date false-positives. Slash-separated dates are
already stopped by the tokenizer because `/` is a delimiter; the parser also
understands `/` when a complete value is supplied internally.

Credit-card candidates are treated differently: a complete 16-digit numeric
chain is evaluated only by CREDIT_CARD rules and must pass a contextual Luhn
check. It is not offered to PHONE or CPF rules. The legacy single-token card
matcher keeps its prior compatibility behavior.

The contextual Luhn implementation is intentional and correct: separators are
removed, exactly 16 digits are required, the existing supported-card prefix
check still applies, and the checksum must be valid. A failed complete card
candidate is not partially offered to PHONE or CPF. The only behavioral
difference is that the historical single-token matcher is preserved unchanged
and may accept input without the same Luhn requirement. This compatibility
choice avoids silently breaking existing callers; making both paths uniform
would require a separately reviewed breaking behavior change to the legacy
matcher.

## Usage

```go
options := analyzer.RunnerOptions{
	ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: true},
}

byteAnalyzer, err := analyzer.MakeByteAnalyzer(ctx, logger, options)
```

With the option omitted or set to `false`, the legacy path remains active.

## Technical architecture changes

### Previous flow

The byte analyzer iterated over the tokenizer output and sent each token to the
configured `RuleRunner`. A matcher could therefore inspect only the bytes of one
token at a time. Anonymization actions referred directly to that token's
original offsets.

```text
input -> tokenizer -> individual token -> RuleRunner -> anonymization action
```

### Contextual flow

When contextual detection is enabled, the analyzer first materializes the
tokenizer output, then builds bounded candidates from adjacent compatible
tokens. Each canonical candidate is evaluated by the same `RuleRunner` used by
the original path. A successful match produces an action whose span covers the
corresponding bytes in the original input. Finally, legacy and contextual
actions are merged and overlaps are resolved before output is written.
A numeric chain that exceeds a configured bound is discarded as a whole rather
than producing a finding for one of its prefixes.

```text
                         +-> individual token -> RuleRunner --+
input -> tokenizer -----+                                  +-> resolve spans -> output
                         +-> bounded candidate -> RuleRunner -+
```

The concurrent implementation does not introduce an unbounded goroutine per
candidate. It submits contextual work to the analyzer's existing fixed-size
token worker pool. The disabled branch continues directly through the legacy
implementation, avoiding contextual candidate allocation.

### New files

- `analyzer/contextual_detection.go`: candidate construction for numeric and
  email entities, canonicalization, bounded scanning, contextual rule
  execution, calendar/date exclusion, cancellation handling, full-chain
  overflow rejection, and deterministic overlap resolution.
- `analyzer/contextual_detection_test.go`: table-driven functional tests,
  serial/concurrent parity tests, boundary and overlap cases, default-off
  compatibility checks, and performance benchmarks.
- `CONTEXTUAL_TOKEN_AGGREGATION.md`: design rationale, operational guidance,
  architecture, file inventory, limits, and verification instructions.

### Modified original files

- `analyzer/factory.go`: adds the public `ContextualDetectionOptions` field to
  `RunnerOptions` and propagates it when byte and string analyzers are created.
- `analyzer/byte_analyzer.go`: selects the contextual execution path only when
  enabled and combines validated contextual actions with normal token actions.
- `pattern/regex.go`: adds an additive Luhn validator used by contextual card
  candidates without changing legacy Visa/Mastercard matcher compatibility.
- `README.md`: documents the opt-in feature, supported entities, configuration,
  and bounded behavior.

No rule format, exception model, or cache API was replaced. Contextual MASK
protects complete aggregate spans and overlap unions while preserving the
configured `MaxSize` for ordinary single-token findings. Aggregate exceptions
do not cancel an independent legacy finding, and cancellation writes no
partially analyzed output. The change is additive and the public option defaults
to `false`.

## Measured performance

Local three-run benchmark medians showed approximately 0% to 2.3% extra time
for marker-free text, with identical allocation counts. Such input takes the
legacy path after a bounded marker scan. Inputs that actually entered contextual
processing took 44.5% to 55.9% more time (51.7% simple mean), while each tested
short operation remained below 8 microseconds.

CPU utilization was not measured with a CPU profiler. Because these benchmarks
are in-memory and CPU-bound, 44.5% to 55.9% is a useful estimate for additional
CPU *per contextual operation*, not for the whole service. The service-wide
effect is diluted by the share of requests that enter this path and must be
confirmed under representative production load. These measurements are not an
SLA.

## Accepted limitations

- The legacy PHONE matcher remains permissive, so unrelated numeric groups can
  still be over-redacted. The feature remains default-off for this reason.
- A numeric run exceeding a bound is discarded as one ambiguous chain. The
  scanner does not restart inside that run, so a phone embedded after a long
  uninterrupted numeric prefix can be missed. This favors avoiding partial or
  manufactured findings.
- Independent legacy findings already identified inside a rejected contextual
  chain remain valid. For example, `11 987654321 +5` can anonymize the phone
  portion while preserving the invalid trailing `+5`.
- Cancellation or worker-pool failure fails closed by writing no output, but the
  current `Anonymize` API has no error return. Callers cannot distinguish that
  result from an empty output through `AnonymizationDetails` alone.
- When the marker gate selects contextual processing, the analyzer materializes
  tokenizer tokens to preserve original spans and resolve overlaps. This uses
  more memory than the streaming legacy path for inputs that actually contain
  numeric or email markers.
- The feature is configured through `MakeByteAnalyzer`/`MakeStringAnalyzer`;
  the lower-level `NewByteAnalyzer` constructor does not expose the option.
- Contextual cards require Luhn while the legacy single-token card matcher keeps
  its historical compatibility behavior, so invalid-Luhn input can differ by
  formatting. This is a documented compatibility limitation, not an error in
  the contextual checksum implementation.

## Verification

The test suite covers fragmented PHONE, CPF, CREDIT_CARD, and EMAIL values; a phone with
every digit separated, with and without `+`; invalid boundaries; exceptions;
Luhn validation; overflow without partial findings; Unicode horizontal spaces;
BR/US/ISO dates and leap years; full-span masking; cancellation; overlapping matches; multiple values;
default-off behavior; and parity between serial and concurrent execution.
Reproducible benchmarks compare the feature enabled and disabled on normal and
PII-containing inputs.

Run all checks with:

```sh
go test -race -count=1 ./...
```
