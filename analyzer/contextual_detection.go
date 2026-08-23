package analyzer

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/Prosus-Cyber-Xchange/leakspok/pattern"
)

const (
	// A card may arrive with every digit tokenized separately. An extra token
	// accommodates an isolated leading plus for phone candidates.
	maxNumericCandidateTokens = 17
	maxEmailCandidateTokens   = 5
	maxNumericCandidateBytes  = 64
	maxEmailCandidateBytes    = 254
	maxNumericCandidateDigits = 16
)

type contextualCandidate struct {
	span  Token
	data  []byte
	rules []Rule
}

type contextualAction struct {
	action anonymizationAction
	entity pattern.Entity
}

func contextualRules(rules []Rule, entities ...pattern.Entity) []Rule {
	selected := make([]Rule, 0, len(rules))
	for _, entity := range entities {
		for _, rule := range rules {
			if rule.Disable || rule.Matcher == nil {
				continue
			}
			if rule.Matcher.Entity() == entity {
				selected = append(selected, rule)
			}
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

func buildContextualCandidates(ctx context.Context, input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate

	numericRules := contextualRules(rules, pattern.EntityCreditCard, pattern.EntityCPF, pattern.EntityPhone)
	if len(numericRules) > 0 {
		candidates = append(candidates, buildNumericCandidates(ctx, input, tokens, numericRules)...)
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
	for len(gap) > 0 {
		char, size := utf8.DecodeRune(gap)
		if char == utf8.RuneError && size == 1 {
			return false
		}
		gap = gap[size:]
		switch {
		case unicode.IsSpace(char) && char != '\n' && char != '\r' && char != '\v' && char != '\f':
		case char == '(' || char == ')':
			if !allowParentheses {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func rulesForNumericDigits(rules []Rule, digits int) []Rule {
	entities := []pattern.Entity{pattern.EntityPhone}
	switch digits {
	case 11:
		entities = []pattern.Entity{pattern.EntityCPF, pattern.EntityPhone}
	case 16:
		entities = []pattern.Entity{pattern.EntityCreditCard}
	}
	return contextualRules(rules, entities...)
}

func parseTwoDigits(value []byte) (int, bool) {
	if len(value) != 2 || value[0] < '0' || value[0] > '9' || value[1] < '0' || value[1] > '9' {
		return 0, false
	}
	return int(value[0]-'0')*10 + int(value[1]-'0'), true
}

func parseFourDigits(value []byte) (int, bool) {
	if len(value) != 4 {
		return 0, false
	}
	result := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, false
		}
		result = result*10 + int(char-'0')
	}
	return result, true
}

func validCalendarDate(year, month, day int) bool {
	if year < 1 || month < 1 || month > 12 || day < 1 {
		return false
	}
	days := [...]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && (year%400 == 0 || year%4 == 0 && year%100 != 0) {
		days[month]++
	}
	return day <= days[month]
}

func isDateSeparator(char byte) bool {
	return char == '-' || char == '.' || char == '/'
}

func parseKnownDate(value []byte) bool {
	if len(value) != 10 {
		return false
	}
	if isDateSeparator(value[4]) && value[7] == value[4] {
		year, yearOK := parseFourDigits(value[:4])
		month, monthOK := parseTwoDigits(value[5:7])
		day, dayOK := parseTwoDigits(value[8:])
		return yearOK && monthOK && dayOK && validCalendarDate(year, month, day)
	}
	if !isDateSeparator(value[2]) || value[5] != value[2] {
		return false
	}
	first, firstOK := parseTwoDigits(value[:2])
	second, secondOK := parseTwoDigits(value[3:5])
	year, yearOK := parseFourDigits(value[6:])
	if !firstOK || !secondOK || !yearOK {
		return false
	}
	return validCalendarDate(year, second, first) || validCalendarDate(year, first, second)
}

func parseCompactTime(value []byte) bool {
	switch len(value) {
	case 2:
		hour, ok := parseTwoDigits(value)
		return ok && hour < 24
	case 4:
		hour, hourOK := parseTwoDigits(value[:2])
		minute, minuteOK := parseTwoDigits(value[2:])
		return hourOK && minuteOK && hour < 24 && minute < 60
	case 5:
		hour, hourOK := parseTwoDigits(value[:2])
		minute, minuteOK := parseTwoDigits(value[3:])
		return value[2] == ':' && hourOK && minuteOK && hour < 24 && minute < 60
	case 8:
		hour, hourOK := parseTwoDigits(value[:2])
		minute, minuteOK := parseTwoDigits(value[3:5])
		second, secondOK := parseTwoDigits(value[6:])
		return value[2] == ':' && value[5] == ':' && hourOK && minuteOK && secondOK &&
			hour < 24 && minute < 60 && second < 60
	default:
		return false
	}
}

func parseKnownTime(value []byte) bool {
	first, remainder := splitHorizontalFields(value)
	if len(remainder) == 0 {
		return parseCompactTime(first)
	}
	second, third := splitHorizontalFields(remainder)
	hour, hourOK := parseTwoDigits(first)
	minute, minuteOK := parseTwoDigits(second)
	if !hourOK || !minuteOK || hour >= 24 || minute >= 60 {
		return false
	}
	if len(third) == 0 {
		return true
	}
	secondValue, secondOK := parseTwoDigits(third)
	return secondOK && secondValue < 60
}

func splitHorizontalFields(value []byte) ([]byte, []byte) {
	for index := 0; index < len(value); {
		char, size := utf8.DecodeRune(value[index:])
		if unicode.IsSpace(char) && char != '\n' && char != '\r' && char != '\v' && char != '\f' {
			end := index + size
			for end < len(value) {
				next, nextSize := utf8.DecodeRune(value[end:])
				if !unicode.IsSpace(next) || next == '\n' || next == '\r' || next == '\v' || next == '\f' {
					break
				}
				end += nextSize
			}
			return value[:index], value[end:]
		}
		index += size
	}
	return value, nil
}

func looksLikeKnownDateTime(value []byte) bool {
	if len(value) < 10 || (!isDateSeparator(value[2]) && !isDateSeparator(value[4])) {
		return false
	}
	date, timeValue := splitHorizontalFields(value)
	if len(date) > 10 && (date[10] == 'T' || date[10] == 't') {
		timeValue = date[11:]
		date = date[:10]
	}
	if !parseKnownDate(date) {
		return false
	}
	return len(timeValue) == 0 || parseKnownTime(timeValue)
}

func excludePhoneForKnownDate(rules []Rule, value []byte) []Rule {
	if !looksLikeKnownDateTime(value) {
		return rules
	}
	selected := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Matcher == nil || rule.Matcher.Entity() != pattern.EntityPhone {
			selected = append(selected, rule)
		}
	}
	return selected
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

func isNumericContinuationToken(token []byte) bool {
	_, _, ok := appendNumericToken(nil, token, false)
	return ok
}

func scanNumericChain(input []byte, tokens []Token, start int) (int, []byte, int, bool, bool) {
	canonical, digits, ok := appendNumericToken(
		make([]byte, 0, maxNumericCandidateBytes),
		tokens[start].Content,
		true,
	)
	if !ok || digits > maxNumericCandidateDigits || len(canonical) > maxNumericCandidateBytes {
		return start, nil, 0, false, false
	}

	end := start
	for next := start + 1; next < len(tokens); next++ {
		if !isHorizontalGap(input[tokens[next-1].End:tokens[next].Start], true) {
			break
		}
		if !isNumericContinuationToken(tokens[next].Content) {
			if isNumericCandidateToken(tokens[next].Content) {
				return end, canonical, digits, true, true
			}
			break
		}
		if next-start+1 > maxNumericCandidateTokens {
			return end, canonical, digits, true, true
		}

		var added int
		canonical, added, ok = appendNumericToken(canonical, tokens[next].Content, false)
		if !ok {
			return end, canonical, digits, true, true
		}
		digits += added
		if digits > maxNumericCandidateDigits || len(canonical) > maxNumericCandidateBytes {
			return end, canonical, digits, true, true
		}
		end = next
	}
	return end, canonical, digits, false, true
}

func buildNumericCandidates(ctx context.Context, input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate
	for start := range tokens {
		if start > 0 &&
			isHorizontalGap(input[tokens[start-1].End:tokens[start].Start], true) &&
			isNumericCandidateToken(tokens[start-1].Content) &&
			isNumericContinuationToken(tokens[start].Content) {
			continue
		}

		end, canonical, digits, overflow, ok := scanNumericChain(input, tokens, start)
		if !ok || overflow || end == start {
			continue
		}
		selectedRules := rulesForNumericDigits(rules, digits)
		original := input[tokens[start].Start:tokens[end].End]
		selectedRules = excludePhoneForKnownDate(selectedRules, original)
		if len(selectedRules) == 0 {
			continue
		}
		if digits == 16 && !pattern.MatchCreditCardLuhn(ctx, canonical) {
			continue
		}
		candidates = append(candidates, contextualCandidate{
			span:  Token{Start: tokens[start].Start, End: tokens[end].End},
			data:  bytes.Clone(canonical),
			rules: selectedRules,
		})
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

func hasEmailContinuation(input []byte, tokens []Token, end int) bool {
	if end+1 >= len(tokens) ||
		!isHorizontalGap(input[tokens[end].End:tokens[end+1].Start], false) {
		return false
	}
	next := tokens[end+1].Content
	return len(next) > 0 && (next[0] == '.' || next[0] == '@')
}

func buildEmailCandidates(input []byte, tokens []Token, rules []Rule) []contextualCandidate {
	var candidates []contextualCandidate
	for start := range tokens {
		if !plausibleEmailStart(tokens[start].Content) || isPlausibleEmail(tokens[start].Content) {
			continue
		}

		canonical := bytes.Clone(tokens[start].Content)
		if len(canonical) > maxEmailCandidateBytes {
			continue
		}
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
			if isPlausibleEmail(canonical) && !hasEmailContinuation(input, tokens, end) {
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

func actionForMatch(span Token, matched Rule, aggregate bool) contextualAction {
	settings := matched.Settings
	if aggregate && settings.Strategy == MASK && settings.Mask != nil {
		mask := *settings.Mask
		mask.MaxSize = span.Len()
		settings.Mask = &mask
	}
	return contextualAction{
		action: anonymizationAction{token: span, settings: settings},
		entity: matched.Matcher.Entity(),
	}
}

func (t *ByteAnalyzer) processContextualCandidate(ctx context.Context, candidate contextualCandidate) (Rule, bool) {
	for start := 0; start < len(candidate.rules); {
		entity := candidate.rules[start].Matcher.Entity()
		end := start + 1
		for end < len(candidate.rules) && candidate.rules[end].Matcher.Entity() == entity {
			end++
		}
		if matched, found := t.ruleRunner.Process(ctx, candidate.rules[start:end], candidate.data); found {
			return matched, true
		}
		start = end
	}
	return Rule{}, false
}

func (t *ByteAnalyzer) anonymizeSequentialContextual(ctx context.Context, rules []Rule, content []byte) ([]contextualAction, bool) {
	tokens := collectTokens(content)
	actions := make([]contextualAction, 0, len(tokens))
	for _, token := range tokens {
		if ctx.Err() != nil {
			return nil, false
		}
		tokenRules := excludePhoneForKnownDate(rules, token.Content)
		if matched, found := t.ruleRunner.Process(ctx, tokenRules, token.Content); found {
			actions = append(actions, actionForMatch(token, matched, false))
		}
	}

	for _, candidate := range buildContextualCandidates(ctx, content, tokens, rules) {
		if ctx.Err() != nil {
			return nil, false
		}
		if matched, found := t.processContextualCandidate(ctx, candidate); found {
			actions = append(actions, actionForMatch(candidate.span, matched, true))
		}
	}
	return actions, ctx.Err() == nil
}

func (t *ByteAnalyzer) anonymizeConcurrentContextual(ctx context.Context, rules []Rule, content []byte) ([]contextualAction, bool) {
	tokens := collectTokens(content)
	candidates := buildContextualCandidates(ctx, content, tokens, rules)

	var actions []contextualAction
	var mu sync.Mutex
	var wg sync.WaitGroup
	complete := true

	submit := func(span Token, data []byte, selectedRules []Rule, aggregate bool) bool {
		wg.Add(1)
		err := t.pool.Submit(func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			candidate := contextualCandidate{span: span, data: data, rules: selectedRules}
			var matched Rule
			var found bool
			if aggregate {
				matched, found = t.processContextualCandidate(ctx, candidate)
			} else {
				matched, found = t.ruleRunner.Process(ctx, selectedRules, data)
			}
			if found {
				mu.Lock()
				actions = append(actions, actionForMatch(span, matched, aggregate))
				mu.Unlock()
			}
		})
		if err != nil {
			wg.Done()
			t.logger.WarnContext(ctx, "Failed to submit contextual anonymization work", "error", err)
			return false
		}
		return true
	}

	for _, token := range tokens {
		tokenRules := excludePhoneForKnownDate(rules, token.Content)
		if !submit(token, token.Content, tokenRules, false) {
			complete = false
			break
		}
	}
	if complete {
		for _, candidate := range candidates {
			if !submit(candidate.span, candidate.data, candidate.rules, true) {
				complete = false
				break
			}
		}
	}
	wg.Wait()
	return actions, complete && ctx.Err() == nil
}

func actionForResolvedSpan(action contextualAction, start, end int) contextualAction {
	widened := action.action.token.Start != start || action.action.token.End != end
	action.action.token.Start = start
	action.action.token.End = end
	if widened && action.action.settings.Strategy == MASK && action.action.settings.Mask != nil {
		mask := *action.action.settings.Mask
		mask.MaxSize = end - start
		action.action.settings.Mask = &mask
	}
	return action
}

func resolveAnonymizationActions(actions []contextualAction) []contextualAction {
	if len(actions) < 2 {
		return actions
	}

	slices.SortFunc(actions, func(a, b contextualAction) int {
		if startDiff := a.action.token.Start - b.action.token.Start; startDiff != 0 {
			return startDiff
		}
		if endDiff := b.action.token.End - a.action.token.End; endDiff != 0 {
			return endDiff
		}
		if a.entity < b.entity {
			return -1
		}
		if a.entity > b.entity {
			return 1
		}
		return 0
	})

	resolved := make([]contextualAction, 0, len(actions))
	best := actions[0]
	bestLength := best.action.token.Len()
	groupStart := best.action.token.Start
	groupEnd := best.action.token.End
	for _, candidate := range actions[1:] {
		if candidate.action.token.Start >= groupEnd {
			resolved = append(resolved, actionForResolvedSpan(best, groupStart, groupEnd))
			best = candidate
			bestLength = candidate.action.token.Len()
			groupStart = candidate.action.token.Start
			groupEnd = candidate.action.token.End
			continue
		}
		groupEnd = max(groupEnd, candidate.action.token.End)
		if candidate.action.token.Len() > bestLength {
			best = candidate
			bestLength = candidate.action.token.Len()
		}
	}
	resolved = append(resolved, actionForResolvedSpan(best, groupStart, groupEnd))
	return resolved
}
