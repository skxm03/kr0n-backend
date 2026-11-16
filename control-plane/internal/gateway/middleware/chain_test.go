package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChainCompiler_FourTierInheritance(t *testing.T) {
	reg := NewRegistry()

	var executionOrder []string

	makeMW := func(name string) MiddlewareFactory {
		return func(cfg map[string]any) (Middleware, error) {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					executionOrder = append(executionOrder, name)
					next.ServeHTTP(w, r)
				})
			}, nil
		}
	}

	_ = reg.Register("global_mw", makeMW("global_mw"))
	_ = reg.Register("service_mw", makeMW("service_mw"))
	_ = reg.Register("group_mw", makeMW("group_mw"))
	_ = reg.Register("profile_mw", makeMW("profile_mw"))
	_ = reg.Register("endpoint_mw", makeMW("endpoint_mw"))

	profiles := map[string][]MiddlewareItem{
		"test_profile": {{Name: "profile_mw"}},
	}
	resolver, _ := NewProfileResolver(profiles)

	compiler := NewChainCompiler(reg, resolver)

	globalItems := []MiddlewareItem{{Name: "global_mw"}}
	serviceItems := []MiddlewareItem{{Name: "service_mw"}}
	groups := []CompiledGroup{
		{
			Name: "auth_group",
			Rules: []GroupMatchRule{
				{Path: "/api/v1/test", Type: MatchExact},
			},
			Middleware: []MiddlewareItem{{Name: "group_mw"}},
		},
	}

	endpoint := EndpointTarget{
		Method:     "GET",
		Path:       "/api/v1/test",
		Use:        []string{"test_profile"},
		Middleware: []MiddlewareItem{{Name: "endpoint_mw"}},
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionOrder = append(executionOrder, "base_handler")
		w.WriteHeader(http.StatusOK)
	})

	handler, err := compiler.CompileEndpoint(baseHandler, globalItems, serviceItems, groups, endpoint)
	if err != nil {
		t.Fatalf("failed to compile endpoint: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	handler.ServeHTTP(rec, req)

	expected := []string{
		"global_mw",
		"service_mw",
		"group_mw",
		"profile_mw",
		"endpoint_mw",
		"base_handler",
	}

	if len(executionOrder) != len(expected) {
		t.Fatalf("expected %d calls, got %d (%v)", len(expected), len(executionOrder), executionOrder)
	}

	for i := range expected {
		if executionOrder[i] != expected[i] {
			t.Errorf("step %d expected %q, got %q", i, expected[i], executionOrder[i])
		}
	}
}
