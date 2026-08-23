package analyzer

import (
	"bytes"
	"context"
	"slices"
	"sync"

	"github.com/Prosus-Cyber-Xchange/leakspok/pattern"
)

const (
	// A phone may arrive with every digit tokenized separately (plus an isolated
	// country-code marker). Keep the scan bounded while covering all 15 digits.
	maxNumericCandidateTokens = 16
	maxEmailCandidateTokens   = 5
	maxNumericCandidateBytes  = 64
	maxEmailCandidateBytes    = 254
	maxNumericCandidateDigits = 15
)

type contextualCandidate struct {
	span  Token
	data  []byte
	rules []Rule
}

type contextualAction struct {
	action   anonymizationAction
	entity   pattern.Entity
	suppress bool
}

func contextualRules(rules []Rule, entities ...pattern.Entity) []Rule {
	selected := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Disable || rule.Matcher == nil {
			continue
		}
		if slices.Contains(entities, rule.Matcher.Entity()) {
			selected = append(selected, rule)
		}
	}
	return selected
}

func collectTokens(input []byte) []Token {
	var tokens []Token
	for token := range TokenIterator(input) {
		tokens = append(tokens, token)
	}
	return tokens
}

func buildContextualCandidates(input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate

	numericRules := contextualRules(rules, pattern.EntityPhone, pattern.EntityCPF)
	if len(numericRules) > 0 {
		candidates = append(candidates, buildNumericCandidates(input, tokens, numericRules)...)
	}

	emailRules := contextualRules(rules, pattern.EntityEmail)
	if len(emailRules) > 0 {
		candidates = append(candidates, buildEmailCandidates(input, tokens, emailRules)...)
	}

	return candidates
}

func isHorizontalGap(gap []byte, allowParentheses bool) bool {
	if len(gap) == 0 {
		return false
	}
	for _, char := range gap {
		switch char {
		case ' ', '\t':
		case '(', ')':
			if !allowParentheses {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func appendNumericToken(dst []byte, token []byte, first bool) ([]byte, int, bool) {
	digits := 0
	for i, char := range token {
		switch {
		case char >= '0' && char <= '9':
			dst = append(dst, char)
			digits++
		case char == '+' && first && i == 0:
			dst = append(dst, char)
		case char == '.' || char == '-':
		default:
			return dst, 0, false
		}
	}
	if digits == 0 && !(first && bytes.Equal(token, []byte("+"))) {
		return dst, 0, false
	}
	return dst, digits, true
}

func isNumericCandidateToken(token []byte) bool {
	_, _, ok := appendNumericToken(nil, token, true)
	return ok
}

//nolint:gocognit // Bounded scanner keeps all stop conditions explicit and local.
func buildNumericCandidates(input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate
	for start := range tokens {
		if start > 0 &&
			isHorizontalGap(input[tokens[start-1].End:tokens[start].Start], true) &&
			isNumericCandidateToken(tokens[start-1].Content) {
			continue
		}

		canonical := make([]byte, 0, maxNumericCandidateBytes)
		var digits int
		var ok bool
		canonical, digits, ok = appendNumericToken(canonical, tokens[start].Content, true)
		if !ok {
			continue
		}

		limit := min(len(tokens), start+maxNumericCandidateTokens)
		for end := start + 1; end < limit; end++ {
			if !isHorizontalGap(input[tokens[end-1].End:tokens[end].Start], true) {
				break
			}

			before := len(canonical)
			var added int
			canonical, added, ok = appendNumericToken(canonical, tokens[end].Content, false)
			if !ok {
				break
			}
			digits += added
			if digits > maxNumericCandidateDigits || len(canonical) > maxNumericCandidateBytes {
				break
			}

			if len(canonical) == before {
				continue
			}
			data := bytes.Clone(canonical)
			candidates = append(candidates, contextualCandidate{
				span:  Token{Start: tokens[start].Start, End: tokens[end].End},
				data:  data,
				rules: rules,
			})
		}
	}
	return candidates
}

func isEmailCandidateByte(char byte) bool {
	if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') {
		return true
	}
	switch char {
	case '@', '.', '_', '+', '-':
		return true
	default:
		return false
	}
}

func validEmailFragment(fragment []byte) bool {
	if len(fragment) == 0 {
		return false
	}
	for _, char := range fragment {
		if !isEmailCandidateByte(char) {
			return false
		}
	}
	return true
}

func canAppendEmailFragment(current, next []byte) bool {
	if !validEmailFragment(next) {
		return false
	}

	at := bytes.IndexByte(current, '@')
	if at < 0 {
		return next[0] == '@' && bytes.Count(next, []byte("@")) == 1
	}
	if bytes.Count(current, []byte("@")) != 1 || bytes.Contains(next, []byte("@")) {
		return false
	}

	domain := current[at+1:]
	if len(domain) == 0 {
		return next[0] != '.'
	}
	if bytes.Contains(domain, []byte(".")) {
		return domain[len(domain)-1] == '.' && next[0] != '.'
	}
	return next[0] == '.'
}

func plausibleEmailStart(token []byte) bool {
	if !validEmailFragment(token) || token[0] == '@' {
		return false
	}
	at := bytes.IndexByte(token, '@')
	return at != 0 && bytes.Count(token, []byte("@")) <= 1
}

func isPlausibleEmail(candidate []byte) bool {
	at := bytes.IndexByte(candidate, '@')
	if at <= 0 || at != bytes.LastIndexByte(candidate, '@') || at == len(candidate)-1 {
		return false
	}
	domain := candidate[at+1:]
	dot := bytes.LastIndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1
}

func buildEmailCandidates(input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate
	for start := range tokens {
		if !plausibleEmailStart(tokens[start].Content) || isPlausibleEmail(tokens[start].Content) {
			continue
		}

		canonical := bytes.Clone(tokens[start].Content)
		limit := min(len(tokens), start+maxEmailCandidateTokens)
		for end := start + 1; end < limit; end++ {
			if !isHorizontalGap(input[tokens[end-1].End:tokens[end].Start], false) ||
				!canAppendEmailFragment(canonical, tokens[end].Content) {
				break
			}
			if len(canonical)+len(tokens[end].Content) > maxEmailCandidateBytes {
				break
			}
			canonical = append(canonical, tokens[end].Content...)
			if isPlausibleEmail(canonical) {
				candidates = append(candidates, contextualCandidate{
					span:  Token{Start: tokens[start].Start, End: tokens[end].End},
					data:  bytes.Clone(canonical),
					rules: rules,
				})
				break
			}
		}
	}
	return candidates
}

func actionForMatch(span Token, matched Rule) contextualAction {
	return contextualAction{
		action: anonymizationAction{token: span, settings: matched.Settings},
		entity: matched.Matcher.Entity(),
	}
}

func exceptionActions(ctx context.Context, candidate contextualCandidate) []contextualAction {
	var actions []contextualAction
	for _, rule := range candidate.rules {
		if isException(ctx, candidate.data, rule.Exceptions) {
			actions = append(actions, contextualAction{
				action: anonymizationAction{token: candidate.span},
				entity: rule.Matcher.Entity(), suppress: true,
			})
		}
	}
	return actions
}

func (t *ByteAnalyzer) anonymizeSequentialContextual(ctx context.Context, rules []Rule, content []byte) []contextualAction {
	tokens := collectTokens(content)
	actions := make([]contextualAction, 0, len(tokens))
	for _, token := range tokens {
		if ctx.Err() != nil {
			break
		}
		if matched, found := t.ruleRunner.Process(ctx, rules, token.Content); found {
			actions = append(actions, actionForMatch(token, matched))
		}
	}

	for _, candidate := range buildContextualCandidates(content, tokens, rules) {
		if ctx.Err() != nil {
			break
		}
		actions = append(actions, exceptionActions(ctx, candidate)...)
		if matched, found := t.ruleRunner.Process(ctx, candidate.rules, candidate.data); found {
			actions = append(actions, actionForMatch(candidate.span, matched))
		}
	}
	return actions
}

func (t *ByteAnalyzer) anonymizeConcurrentContextual(ctx context.Context, rules []Rule, content []byte) []contextualAction {
	tokens := collectTokens(content)
	candidates := buildContextualCandidates(content, tokens, rules)

	var actions []contextualAction
	var mu sync.Mutex
	var wg sync.WaitGroup

	submit := func(span Token, data []byte, selectedRules []Rule) bool {
		wg.Add(1)
		err := t.pool.Submit(func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			exceptions := exceptionActions(ctx, contextualCandidate{span: span, data: data, rules: selectedRules})
			if matched, found := t.ruleRunner.Process(ctx, selectedRules, data); found {
				mu.Lock()
				actions = append(actions, exceptions...)
				actions = append(actions, actionForMatch(span, matched))
				mu.Unlock()
			} else if len(exceptions) > 0 {
				mu.Lock()
				actions = append(actions, exceptions...)
				mu.Unlock()
			}
		})
		if err != nil {
			wg.Done()
			return false
		}
		return true
	}

	for _, token := range tokens {
		if !submit(token, token.Content, rules) {
			break
		}
	}
	for _, candidate := range candidates {
		if !submit(candidate.span, candidate.data, candidate.rules) {
			break
		}
	}
	wg.Wait()
	return actions
}

//nolint:gocognit // Sweep combines suppression indexing and deterministic overlap resolution.
func resolveAnonymizationActions(actions []contextualAction) []contextualAction {
	type suppressionIndex struct {
		spans   []Token
		maxEnds []int
	}

	indexes := make(map[pattern.Entity]*suppressionIndex)
	for _, action := range actions {
		if action.suppress {
			index := indexes[action.entity]
			if index == nil {
				index = &suppressionIndex{}
				indexes[action.entity] = index
			}
			index.spans = append(index.spans, action.action.token)
		}
	}
	for _, index := range indexes {
		slices.SortFunc(index.spans, func(a, b Token) int { return a.Start - b.Start })
		index.maxEnds = make([]int, len(index.spans))
		maxEnd := 0
		for i, span := range index.spans {
			maxEnd = max(maxEnd, span.End)
			index.maxEnds[i] = maxEnd
		}
	}

	filtered := actions[:0]
	for _, action := range actions {
		if action.suppress {
			continue
		}
		suppressed := false
		if index := indexes[action.entity]; index != nil {
			position, _ := slices.BinarySearchFunc(index.spans, action.action.token.Start, func(span Token, start int) int {
				return span.Start - start
			})
			for position < len(index.spans) && index.spans[position].Start <= action.action.token.Start {
				position++
			}
			if position > 0 && index.maxEnds[position-1] >= action.action.token.End {
				suppressed = true
			}
		}
		if !suppressed {
			filtered = append(filtered, action)
		}
	}
	actions = filtered

	if len(actions) < 2 {
		return actions
	}

	slices.SortStableFunc(actions, func(a, b contextualAction) int {
		if startDiff := a.action.token.Start - b.action.token.Start; startDiff != 0 {
			return startDiff
		}
		return b.action.token.End - a.action.token.End
	})

	resolved := make([]contextualAction, 0, len(actions))
	best := actions[0]
	groupEnd := best.action.token.End
	for _, candidate := range actions[1:] {
		if candidate.action.token.Start >= groupEnd {
			resolved = append(resolved, best)
			best = candidate
			groupEnd = candidate.action.token.End
			continue
		}

		if candidate.action.token.End > groupEnd {
			groupEnd = candidate.action.token.End
		}
		if candidate.action.token.Len() > best.action.token.Len() {
			best = candidate
		}
	}
	resolved = append(resolved, best)
	return resolved
}
