package middleware

import (
	"path"
	"strings"
)

// MatchType defines the URL matching strategy.
type MatchType string

const (
	MatchExact    MatchType = "exact"
	MatchPrefix   MatchType = "prefix"
	MatchTemplate MatchType = "template"
)

// GroupMatchRule defines a compiled rule for matching request endpoints.
type GroupMatchRule struct {
	Path    string
	Type    MatchType
	Methods map[string]bool // empty map = all methods allowed
}

// Matches evaluates whether an incoming method and path satisfy the rule.
func (r GroupMatchRule) Matches(method, reqPath string) bool {
	// 1. Method check
	if len(r.Methods) > 0 {
		if !r.Methods[strings.ToUpper(method)] {
			return false
		}
	}

	normReq := path.Clean("/" + strings.TrimSpace(reqPath))
	normRule := path.Clean("/" + strings.TrimSpace(r.Path))

	switch r.Type {
	case MatchPrefix:
		rulePrefix := normRule
		if strings.HasSuffix(strings.TrimSpace(r.Path), "/*") {
			rulePrefix = path.Clean(strings.TrimSuffix(strings.TrimSpace(r.Path), "/*"))
		}
		if normReq == rulePrefix || strings.HasPrefix(normReq, rulePrefix+"/") {
			return true
		}
		return false

	case MatchTemplate:
		return matchTemplate(normRule, normReq)

	case MatchExact:
		fallthrough
	default:
		return normReq == normRule
	}
}

func matchTemplate(pattern, target string) bool {
	patternSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	targetSegs := strings.Split(strings.Trim(target, "/"), "/")

	if len(patternSegs) != len(targetSegs) {
		return false
	}

	for i := range patternSegs {
		pSeg := patternSegs[i]
		tSeg := targetSegs[i]

		if strings.HasPrefix(pSeg, "{") && strings.HasSuffix(pSeg, "}") {
			// Parameter wildcard: matches any non-empty segment
			if tSeg == "" {
				return false
			}
			continue
		}

		if pSeg != tSeg {
			return false
		}
	}

	return true
}

// CompiledGroup bundles group matching rules with the group's declared middleware items.
type CompiledGroup struct {
	Name       string
	Rules      []GroupMatchRule
	Middleware []MiddlewareItem
}

// Matches reports whether method and reqPath match any rule in this group.
func (g CompiledGroup) Matches(method, reqPath string) bool {
	for _, rule := range g.Rules {
		if rule.Matches(method, reqPath) {
			return true
		}
	}
	return false
}
