package policy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const labelKeyText = `[A-Za-z0-9][A-Za-z0-9._/-]{0,126}`

var (
	labelKeyPattern   = regexp.MustCompile(`^` + labelKeyText + `$`)
	labelValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	setClausePattern  = regexp.MustCompile(`^(` + labelKeyText + `)\s+(?i:(notin|in))\s*\(([^()]*)\)$`)
	binaryPattern     = regexp.MustCompile(`^(` + labelKeyText + `)\s*(==|!=|=)\s*(\S+)\s*$`)
)

type selectorClause struct {
	key    string
	op     string
	values []string
}

type parsedSelector []selectorClause

func parseSelector(expression string) (string, parsedSelector, error) {
	if len(expression) == 0 || len(expression) > 1024 {
		return "", nil, errors.New("selector length must be between 1 and 1024 bytes")
	}
	parts, err := splitSelector(expression)
	if err != nil {
		return "", nil, err
	}
	if len(parts) > 32 {
		return "", nil, errors.New("selector may contain at most 32 clauses")
	}

	clauses := make(parsedSelector, 0, len(parts))
	canonical := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for index, part := range parts {
		clause, text, err := parseSelectorClause(part)
		if err != nil {
			return "", nil, fmt.Errorf("selector clause %d is invalid", index)
		}
		if _, exists := seen[text]; exists {
			return "", nil, fmt.Errorf("selector clause %d is duplicated", index)
		}
		seen[text] = struct{}{}
		clauses = append(clauses, clause)
		canonical = append(canonical, text)
	}
	sort.SliceStable(clauses, func(i, j int) bool {
		return canonicalClause(clauses[i]) < canonicalClause(clauses[j])
	})
	sort.Strings(canonical)
	return strings.Join(canonical, ","), clauses, nil
}

func splitSelector(expression string) ([]string, error) {
	var parts []string
	start := 0
	depth := 0
	for index, r := range expression {
		switch r {
		case '(':
			depth++
			if depth > 1 {
				return nil, errors.New("selector parentheses may not be nested")
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("selector parentheses are unbalanced")
			}
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(expression[start:index])
				if part == "" {
					return nil, errors.New("selector contains an empty clause")
				}
				parts = append(parts, part)
				start = index + 1
			}
		}
	}
	if depth != 0 {
		return nil, errors.New("selector parentheses are unbalanced")
	}
	part := strings.TrimSpace(expression[start:])
	if part == "" {
		return nil, errors.New("selector contains an empty clause")
	}
	return append(parts, part), nil
}

func parseSelectorClause(part string) (selectorClause, string, error) {
	if matches := setClausePattern.FindStringSubmatch(part); matches != nil {
		key := strings.ToLower(matches[1])
		op := strings.ToLower(matches[2])
		rawValues := strings.Split(matches[3], ",")
		values := make([]string, 0, len(rawValues))
		seen := make(map[string]struct{}, len(rawValues))
		for _, raw := range rawValues {
			value := strings.ToLower(strings.TrimSpace(raw))
			if !labelValuePattern.MatchString(value) {
				return selectorClause{}, "", errors.New("invalid set value")
			}
			if _, exists := seen[value]; exists {
				return selectorClause{}, "", errors.New("duplicate set value")
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
		sort.Strings(values)
		clause := selectorClause{key: key, op: op, values: values}
		return clause, canonicalClause(clause), nil
	}
	if matches := binaryPattern.FindStringSubmatch(part); matches != nil {
		key := strings.ToLower(matches[1])
		op := matches[2]
		if op == "==" {
			op = "="
		}
		value := strings.ToLower(matches[3])
		if !labelValuePattern.MatchString(value) {
			return selectorClause{}, "", errors.New("invalid comparison value")
		}
		clause := selectorClause{key: key, op: op, values: []string{value}}
		return clause, canonicalClause(clause), nil
	}
	if labelKeyPattern.MatchString(part) {
		clause := selectorClause{key: strings.ToLower(part), op: "exists"}
		return clause, canonicalClause(clause), nil
	}
	return selectorClause{}, "", errors.New("unsupported selector clause")
}

func canonicalClause(clause selectorClause) string {
	switch clause.op {
	case "exists":
		return clause.key
	case "in", "notin":
		return clause.key + " " + clause.op + " (" + strings.Join(clause.values, ",") + ")"
	default:
		return clause.key + clause.op + clause.values[0]
	}
}

func (selector parsedSelector) matches(labels map[string]string) bool {
	for _, clause := range selector {
		value, exists := labels[clause.key]
		if !exists {
			return false
		}
		switch clause.op {
		case "exists":
			continue
		case "=":
			if value != clause.values[0] {
				return false
			}
		case "!=":
			if value == clause.values[0] {
				return false
			}
		case "in":
			if !containsString(clause.values, value) {
				return false
			}
		case "notin":
			if containsString(clause.values, value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

// MatchSelector validates a selector and evaluates it against a normalized
// copy of labels. Callers never need to expose selector or label contents in
// logs in order to use the matcher.
func MatchSelector(expression string, labels map[string]string) (bool, error) {
	_, selector, err := parseSelector(expression)
	if err != nil {
		return false, err
	}

	normalized := make(map[string]string, len(labels))
	for key, value := range labels {
		normalized[strings.ToLower(key)] = strings.ToLower(value)
	}
	return selector.matches(normalized), nil
}
