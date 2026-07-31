package server

import (
	"context"
	"errors"
	"testing"
)

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
