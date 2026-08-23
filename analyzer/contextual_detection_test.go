package analyzer_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Prosus-Cyber-Xchange/leakspok/analyzer"
	"github.com/Prosus-Cyber-Xchange/leakspok/pattern"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func contextualRule(entity pattern.Entity, strategy analyzer.AnonymizeStrategy) analyzer.Rule {
	var matcher analyzer.Matcher
	switch entity { //nolint:exhaustive // Helper intentionally supports only contextual entities.
	case pattern.EntityPhone:
		matcher = pattern.PhoneMatcher()
	case pattern.EntityCPF:
		matcher = pattern.CPFMatcher()
	case pattern.EntityEmail:
		matcher = pattern.EmailMatcher()
	case pattern.EntityCreditCard:
		matcher = pattern.CreditCardMatcher()
	default:
		panic("unsupported contextual test entity")
	}

	settings := analyzer.RuleSettings{Strategy: strategy}
	if strategy == analyzer.REDACT {
		settings.Redact = &analyzer.RedactSettings{Placeholder: "<" + string(entity) + ">"}
	} else {
		settings.Mask = &analyzer.MaskSettings{MaskingChar: "*", MaxSize: 3}
	}

	return analyzer.Rule{Name: string(entity), Matcher: matcher, Settings: settings}
}

func makeContextualAnalyzer(t *testing.T, concurrent bool) analyzer.ByteAnalyzer {
	t.Helper()

	options := analyzer.RunnerOptions{
		ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: true},
	}
	if concurrent {
		options.Concurrency = analyzer.ConcurrencyOptions{
			Enabled:                   true,
			ConcurrentTokenProcessing: true,
			TokenPoolSize:             4,
		}
	}

	ba, err := analyzer.MakeByteAnalyzer(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		options,
	)
	require.NoError(t, err)
	t.Cleanup(ba.Stop)
	return ba
}

func anonymizeContextual(t *testing.T, ba analyzer.ByteAnalyzer, rules []analyzer.Rule, input string) (string, analyzer.AnonymizationDetails) {
	t.Helper()
	var output bytes.Buffer
	details := ba.Anonymize(context.Background(), rules, &output, []byte(input))
	return output.String(), details
}

func TestContextualDetectionPhone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"country and area code", "+55 54 99912 0654", "<PHONE>"},
		{"without plus", "55 54 99912 0654", "<PHONE>"},
		{"domestic", "54 99912 0654", "<PHONE>"},
		{"isolated plus", "+ 55 54 99912 0654", "<PHONE>"},
		{"parentheses and hyphen", "+55 (54) 99912-0654", "<PHONE>"},
		{"every digit separated by spaces", "+ 5 5 5 4 9 9 9 1 2 0 6 5 4", "<PHONE>"},
		{"every digit separated without plus", "5 5 5 4 9 9 9 1 2 0 6 5 4", "<PHONE>"},
		{"surrounding text", "ligue para +55 54 99912 0654 amanhã", "ligue para <PHONE> amanhã"},
		{"two values", "+55 54 99912 0654 e +55 11 98888 7777", "<PHONE> e <PHONE>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ba := makeContextualAnalyzer(t, false)
			output, details := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, tt.input)
			assert.Equal(t, tt.expected, output)
			assert.True(t, details.HasFindings)
			assert.ElementsMatch(t, []pattern.Entity{pattern.EntityPhone}, details.DetectedEntities)
			assert.ElementsMatch(t, []pattern.Entity{pattern.EntityPhone}, details.AnonymizedEntities)
		})
	}
}

func TestContextualDetectionPhoneStopsAtInvalidBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"+ 55 54 das 99 dsad", "+ 55 54 das 99 dsad"},
		{"+55 54 abc 99912 0654", "+55 54 abc <PHONE>"},
		{"55 código 54 código 99912", "55 código 54 código 99912"},
		{"+55 54\n99912 0654", "+55 54\n<PHONE>"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			ba := makeContextualAnalyzer(t, false)
			output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, tt.input)
			assert.Equal(t, tt.expected, output)
		})
	}
}

func TestContextualDetectionCPF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"spaces", "529 982 247 25", "<CPF_NUMBER>"},
		{"formatted prefix", "529.982.247 25", "<CPF_NUMBER>"},
		{"mixed punctuation", "529 982.247-25", "<CPF_NUMBER>"},
		{"invalid checksum", "529 982 247 24", "529 982 247 24"},
		{"word boundary", "529 982 abc 247 25", "529 982 abc 247 25"},
		{"newline boundary", "529 982\n247 25", "529 982\n247 25"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ba := makeContextualAnalyzer(t, false)
			output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityCPF, analyzer.REDACT)}, tt.input)
			assert.Equal(t, tt.expected, output)
		})
	}
}

func TestContextualDetectionCreditCard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"groups separated by spaces", "5200 1000 0000 2803"},
		{"mixed spaces and dashes", "5200-1000 0000-2803"},
		{"every digit separated", "5 2 0 0 1 0 0 0 0 0 0 0 2 8 0 3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ba := makeContextualAnalyzer(t, false)
			output, details := anonymizeContextual(t, ba, []analyzer.Rule{
				contextualRule(pattern.EntityPhone, analyzer.REDACT),
				contextualRule(pattern.EntityCreditCard, analyzer.REDACT),
			}, tt.input)
			assert.Equal(t, "<CREDIT_CARD>", output)
			assert.Contains(t, details.DetectedEntities, pattern.EntityCreditCard)
			assert.ElementsMatch(t, []pattern.Entity{pattern.EntityCreditCard}, details.AnonymizedEntities)
		})
	}
}

func TestContextualDetectionDoesNotRedactNumericPrefixBeyondBounds(t *testing.T) {
	t.Parallel()

	input := "4539 1488 0343 6467 9"
	ba := makeContextualAnalyzer(t, false)
	output, details := anonymizeContextual(t, ba, []analyzer.Rule{
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityCreditCard, analyzer.REDACT),
	}, input)
	assert.Equal(t, input, output)
	assert.False(t, details.HasFindings)
}

func TestContextualDetectionRejectsInvalidCardChecksum(t *testing.T) {
	t.Parallel()

	input := "5200 1000 0000 2806"
	ba := makeContextualAnalyzer(t, false)
	output, details := anonymizeContextual(t, ba, []analyzer.Rule{
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityCreditCard, analyzer.REDACT),
	}, input)
	assert.Equal(t, input, output)
	assert.False(t, details.HasFindings)
}

func TestContextualDetectionEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"space after at", "test@ example.com", "<EMAIL>"},
		{"space before at", "test @example.com", "<EMAIL>"},
		{"spaces around at", "test @ example.com", "<EMAIL>"},
		{"space before suffix", "test@example .com", "<EMAIL>"},
		{"fully fragmented", "test @ example . com", "<EMAIL>"},
		{"does not redact bounded prefix", "test @ example . com . br", "test @ example . com . br"},
		{"missing local", "@ example.com", "@ example.com"},
		{"missing domain", "test @", "test @"},
		{"word after at", "test @ isso nao e dominio example . com", "test @ isso nao e dominio example . com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ba := makeContextualAnalyzer(t, false)
			output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityEmail, analyzer.REDACT)}, tt.input)
			assert.Equal(t, tt.expected, output)
		})
	}
}

func TestContextualDetectionOverlapPrefersFullSpan(t *testing.T) {
	t.Parallel()

	ba := makeContextualAnalyzer(t, false)
	output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, "+55 54 99912-0654")
	assert.Equal(t, "<PHONE>", output)
}

func TestContextualDetectionPreservesMaskSemanticsOnOriginalRange(t *testing.T) {
	t.Parallel()

	ba := makeContextualAnalyzer(t, false)
	output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.MASK)}, "+55 54 99912 0654")
	assert.Equal(t, "*****************", output)
}

func TestContextualDetectionSupportsUnicodeHorizontalSpaces(t *testing.T) {
	t.Parallel()

	ba := makeContextualAnalyzer(t, false)
	output, _ := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, "+55\u00a054\u202f99912 0654")
	assert.Equal(t, "<PHONE>", output)
}

func TestContextualDetectionCancellationWritesNothing(t *testing.T) {
	t.Parallel()

	ba := makeContextualAnalyzer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	details := ba.Anonymize(ctx, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, &output, []byte("+55 54 99912 0654"))
	assert.Empty(t, output.String())
	assert.False(t, details.HasFindings)
}

func TestContextualDetectionHonorsCanonicalException(t *testing.T) {
	t.Parallel()

	rule := contextualRule(pattern.EntityPhone, analyzer.REDACT)
	rule.Exceptions = []analyzer.Exception{{
		Reason: "synthetic safe value",
		Matcher: pattern.NewPatternMatcher(
			"EXCEPTION",
			pattern.Equal([]byte("+5554999120654")),
		),
	}}

	ba := makeContextualAnalyzer(t, false)
	output, details := anonymizeContextual(t, ba, []analyzer.Rule{rule}, "+55 54 99912 0654")
	assert.Equal(t, "+55 54 99912 0654", output)
	assert.False(t, details.HasFindings)
}

func TestContextualExceptionDoesNotSuppressLegacyFinding(t *testing.T) {
	t.Parallel()

	rule := contextualRule(pattern.EntityPhone, analyzer.REDACT)
	rule.Exceptions = []analyzer.Exception{{
		Reason: "aggregate-only exception",
		Matcher: pattern.NewPatternMatcher(
			"EXCEPTION",
			pattern.Equal([]byte("123456789")),
		),
	}}

	ba := makeContextualAnalyzer(t, false)
	output, details := anonymizeContextual(t, ba, []analyzer.Rule{rule}, "1234567 89")
	assert.Equal(t, "<PHONE> 89", output)
	assert.True(t, details.HasFindings)
}

func TestContextualDetectionLegacyDefaultRemainsDisabled(t *testing.T) {
	t.Parallel()

	ba, err := analyzer.MakeByteAnalyzer(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), analyzer.RunnerOptions{})
	require.NoError(t, err)
	output, details := anonymizeContextual(t, ba, []analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)}, "+55 54 99912 0654")
	assert.Equal(t, "+55 54 99912 0654", output)
	assert.False(t, details.HasFindings)
}

func TestContextualDetectionStringAnalyzer(t *testing.T) {
	t.Parallel()

	sa, err := analyzer.MakeStringAnalyzer(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		analyzer.RunnerOptions{
			ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: true},
		},
	)
	require.NoError(t, err)
	t.Cleanup(sa.Stop)

	output, details := sa.Anonymize(
		context.Background(),
		[]analyzer.Rule{contextualRule(pattern.EntityPhone, analyzer.REDACT)},
		"+55 54 99912 0654",
	)
	assert.Equal(t, "<PHONE>", output)
	assert.True(t, details.HasFindings)
}

func TestContextualDetectionSerialAndConcurrentParity(t *testing.T) {
	t.Parallel()

	input := "fone +55 54 99912 0654 cpf 529 982 247 25 email test @ example . com"
	rules := []analyzer.Rule{
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityCPF, analyzer.REDACT),
		contextualRule(pattern.EntityEmail, analyzer.REDACT),
	}

	serialOutput, serialDetails := anonymizeContextual(t, makeContextualAnalyzer(t, false), rules, input)
	concurrentOutput, concurrentDetails := anonymizeContextual(t, makeContextualAnalyzer(t, true), rules, input)

	assert.Equal(t, serialOutput, concurrentOutput)
	assert.Equal(t, serialDetails.HasFindings, concurrentDetails.HasFindings)
	assert.ElementsMatch(t, serialDetails.DetectedEntities, concurrentDetails.DetectedEntities)
	assert.ElementsMatch(t, serialDetails.AnonymizedEntities, concurrentDetails.AnonymizedEntities)
}

func BenchmarkByteAnalyzerContextual(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ba, err := analyzer.MakeByteAnalyzer(context.Background(), logger, analyzer.RunnerOptions{
		ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: true},
	})
	require.NoError(b, err)

	rules := []analyzer.Rule{
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityCPF, analyzer.REDACT),
		contextualRule(pattern.EntityEmail, analyzer.REDACT),
	}

	normalChunk := []byte("ordinary application text without sensitive values; ")
	inputs := map[string][]byte{
		"Normal1KiB":         bytes.Repeat(normalChunk, 22),
		"Normal16KiB":        bytes.Repeat(normalChunk, 350),
		"Normal64KiB":        bytes.Repeat(normalChunk, 1400),
		"PhoneSingle":        []byte("contact +5554999120654 today"),
		"PhoneFragmented":    []byte("contact +55 54 99912 0654 today"),
		"CPFFragmented":      []byte("document 529 982 247 25"),
		"EmailFragmented":    []byte("contact test @ example . com"),
		"NumericAdversarial": bytes.Repeat([]byte("x 1 2 3 4 5 6 7 8 y "), 256),
	}

	for name, input := range inputs {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var output bytes.Buffer
				_ = ba.Anonymize(context.Background(), rules, &output, input)
			}
		})
	}
}

func BenchmarkContextualDetectionOverhead(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rules := []analyzer.Rule{
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityCPF, analyzer.REDACT),
		contextualRule(pattern.EntityEmail, analyzer.REDACT),
	}

	normalChunk := []byte("ordinary application text without sensitive values; ")
	inputs := map[string][]byte{
		"Normal1KiB":      bytes.Repeat(normalChunk, 22),
		"Normal16KiB":     bytes.Repeat(normalChunk, 350),
		"Normal64KiB":     bytes.Repeat(normalChunk, 1400),
		"PhoneFragmented": []byte("contact +55 54 99912 0654 today"),
		"CPFFragmented":   []byte("document 529 982 247 25"),
		"EmailFragmented": []byte("contact test @ example . com"),
	}

	for _, enabled := range []bool{false, true} {
		mode := "Disabled"
		if enabled {
			mode = "Enabled"
		}
		ba, err := analyzer.MakeByteAnalyzer(context.Background(), logger, analyzer.RunnerOptions{
			ContextualDetection: analyzer.ContextualDetectionOptions{Enabled: enabled},
		})
		require.NoError(b, err)

		for name, input := range inputs {
			b.Run(mode+"/"+name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var output bytes.Buffer
					_ = ba.Anonymize(context.Background(), rules, &output, input)
				}
			})
		}
		ba.Stop()
	}
}
