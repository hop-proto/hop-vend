package server

import (
	"context"
	"errors"
	"testing"
)

func TestClaimAuthorizer(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{name: "scalar", claims: map[string]any{"tenant": "hop"}, want: true},
		{name: "string array", claims: map[string]any{"tenant": []string{"other", "hop"}}, want: true},
		{name: "JSON array", claims: map[string]any{"tenant": []any{"other", "hop"}}, want: true},
		{name: "wrong value", claims: map[string]any{"tenant": "other"}},
		{name: "missing claim", claims: map[string]any{}},
	}
	authorizer := ClaimAuthorizer{Claim: "tenant", Value: "hop"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.Authorize(context.Background(), &Principal{Claims: test.claims})
			if test.want && err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if !test.want && !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Authorize() error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestAuthenticatedAuthorizerRequiresCompletePrincipal(t *testing.T) {
	authorizer := AuthenticatedAuthorizer{}
	if err := authorizer.Authorize(context.Background(), &Principal{
		Subject: "issuer#subject",
		Name:    "person",
	}); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := authorizer.Authorize(context.Background(), &Principal{Name: "person"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize() error = %v, want ErrUnauthorized", err)
	}
}
