package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ErrUnauthorized marks an authenticated principal that is not permitted to
// receive a credential.
var ErrUnauthorized = errors.New("principal is not authorized")

// AuthTransaction binds a browser authentication flow to a pending enrollment.
type AuthTransaction struct {
	State string
	Nonce string
}

// Principal is an authenticated identity normalized across providers.
type Principal struct {
	Subject string
	Name    string
	Claims  map[string]any

	session any
}

// Authenticator performs a browser authentication flow and returns a verified
// principal.
type Authenticator interface {
	Begin(http.ResponseWriter, *http.Request, AuthTransaction) error
	State(*http.Request) (string, error)
	Complete(context.Context, *http.Request, AuthTransaction) (*Principal, error)
}

// Authorizer decides whether an authenticated principal may receive a
// credential.
type Authorizer interface {
	Authorize(context.Context, *Principal) error
}

// AuthenticatedAuthorizer permits every successfully authenticated principal.
type AuthenticatedAuthorizer struct{}

// Authorize permits principals with both a stable subject and certificate
// name.
func (AuthenticatedAuthorizer) Authorize(_ context.Context, principal *Principal) error {
	if principal == nil || principal.Subject == "" || principal.Name == "" {
		return fmtUnauthorized("authenticated principal is incomplete")
	}
	return nil
}

func fmtUnauthorized(message string) error {
	return fmt.Errorf("%w: %s", ErrUnauthorized, message)
}
