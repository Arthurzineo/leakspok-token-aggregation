package analyzer_test

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/Prosus-Cyber-Xchange/leakspok/analyzer"
	"github.com/Prosus-Cyber-Xchange/leakspok/pattern"
	"github.com/stretchr/testify/require"
)

type corpusNode struct {
	Text     string       `xml:",chardata"`
	Children []corpusNode `xml:",any"`
}

func (n corpusNode) appendText(builder *strings.Builder) {
	builder.WriteString(n.Text)
	for _, child := range n.Children {
		child.appendText(builder)
		builder.WriteByte(' ')
	}
}

func TestCarolinaCorpusProbe(t *testing.T) {
	corpusPath := os.Getenv("CAROLINA_CORPUS_GZ")
	if corpusPath == "" {
		t.Skip("set CAROLINA_CORPUS_GZ to run the opt-in corpus comparison")
	}
	file, err := os.Open(corpusPath)
	require.NoError(t, err)
	defer file.Close()
	zipped, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer zipped.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	legacy, err := analyzer.MakeByteAnalyzer(context.Background(), logger, analyzer.RunnerOptions{})
	require.NoError(t, err)
	contextual := makeContextualAnalyzer(t, false)
	rules := []analyzer.Rule{
		contextualRule(pattern.EntityCreditCard, analyzer.REDACT),
		contextualRule(pattern.EntityCPF, analyzer.REDACT),
		contextualRule(pattern.EntityPhone, analyzer.REDACT),
		contextualRule(pattern.EntityEmail, analyzer.REDACT),
	}
	markers := []string{"<CREDIT_CARD>", "<CPF_NUMBER>", "<PHONE>", "<EMAIL>"}
	totalsLegacy := make([]int, len(markers))
	totalsContextual := make([]int, len(markers))

	decoder := xml.NewDecoder(zipped)
	documents, changed, totalBytes := 0, 0, 0
	for {
		token, decodeErr := decoder.Token()
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		require.NoError(t, decodeErr)
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "text" {
			continue
		}
		var node corpusNode
		require.NoError(t, decoder.DecodeElement(&node, &start))
		var textBuilder strings.Builder
		node.appendText(&textBuilder)
		text := textBuilder.String()
		if strings.TrimSpace(text) == "" {
			continue
		}
		documents++
		totalBytes += len(text)
		var legacyOutput, contextualOutput strings.Builder
		legacy.Anonymize(context.Background(), rules, &legacyOutput, []byte(text))
		contextual.Anonymize(context.Background(), rules, &contextualOutput, []byte(text))
		different := false
		for index, marker := range markers {
			before := strings.Count(legacyOutput.String(), marker)
			after := strings.Count(contextualOutput.String(), marker)
			totalsLegacy[index] += before
			totalsContextual[index] += after
			different = different || before != after
		}
		if different {
			changed++
		}
	}
	t.Logf("documents=%d bytes=%d changed=%d markers=%v legacy=%v contextual=%v", documents, totalBytes, changed, markers, totalsLegacy, totalsContextual)
}
