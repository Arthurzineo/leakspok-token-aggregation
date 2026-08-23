# Contextual token aggregation

## Motivation

Leakspok normally evaluates each tokenizer output independently. That fast path
works for values contained in one token, but formatted PII may be split into
several tokens. Examples include `+55 54 99912 0654`,
`5 5 5 4 9 9 9 1 2 0 6 5 4`, `529 982 247 25`, and
`test @ example . com`. None of the individual fragments is sufficient for the
existing PHONE, CPF, or EMAIL matcher, even though the complete value is PII.

The new opt-in contextual path joins only adjacent, compatible fragments into a
canonical candidate, validates that candidate with the existing matchers, and
applies the selected anonymization strategy to the complete original byte span.
This preserves the established rule, exception, cache, masking, and redaction
semantics instead of introducing a second matching system.

## Design and safety bounds

- Disabled by default through `RunnerOptions.ContextualDetection.Enabled`.
- Limited initially to PHONE, CPF, and EMAIL rules.
- Numeric candidates accept only digits and an allowlisted set of formatting
  characters. They are bounded to 16 tokens, 64 bytes, and 15 digits.
- Email candidates use a small, allowlisted grammar and are bounded to 5 tokens
  and 254 bytes.
- Words, newlines, and unsupported separators stop aggregation.
- Findings retain offsets into the original input; formatting is never silently
  removed from the output.
- Overlapping findings are resolved deterministically, preferring the largest
  validated span.
- Candidate scanning is bounded and overlap resolution is `O(n log n)`.
- The existing bounded worker pool is reused in concurrent mode.

These constraints are important because unrestricted token concatenation could
create false positives, join unrelated data, or cause excessive CPU and memory
use on adversarial input.

## Usage

```go
options := analyzer.RunnerOptions{
	ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: true},
}

byteAnalyzer, err := analyzer.MakeByteAnalyzer(ctx, logger, options)
```

With the option omitted or set to `false`, the legacy path remains active.

## Verification

The test suite covers fragmented PHONE, CPF, and EMAIL values; a phone with
every digit separated, with and without `+`; invalid boundaries; exceptions;
masking; overlapping matches; multiple values; default-off behavior; and parity
between serial and concurrent execution. Reproducible benchmarks compare the
feature enabled and disabled on normal and PII-containing inputs.

Run all checks with:

```sh
go test -race -count=1 ./...
```
