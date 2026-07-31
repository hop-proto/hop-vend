package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/vend/server/config"
)

// TestGitHubFlow exercises the login and callback handlers with a mocked
// GitHub OAuth and API server.
func TestGitHubFlow(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request: %v", err)
		}
		if r.Form.Get("code") != "code" {
			t.Fatalf("unexpected code: %q", r.Form.Get("code"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok","token_type":"bearer"}`)
	})
	ghMux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("authorization header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser","id":1234,"type":"User"}`)
	})
	ghMux.HandleFunc("/user/memberships/orgs/testorg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"state":"active","role":"member"}`)
	})
	githubServer := httptest.NewServer(ghMux)
	defer githubServer.Close()

	cfg := &config.Config{
		IntermediateCAPath:  "../intermediate.pem",
		IntermediateKeyPath: "../intermediate.key.pem",
		CertValidity:        time.Hour,
		RequestTimeout:      10 * time.Minute,
		PublicURL:           "https://vend.example",
		HopServerName:       "vend-server",
	}
	authenticator := NewGitHubAuthenticator(GitHubAuthenticatorConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  cfg.PublicURL + "/callback",
		APIBaseURL:   githubServer.URL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  githubServer.URL + "/auth",
			TokenURL: githubServer.URL + "/token",
		},
	})
	srv := NewWithAuth(cfg, authenticator, GitHubOrganizationAuthorizer{Organization: "testorg"})
	clientKey := keys.GenerateNewX25519KeyPair()
	requestID, pending, err := srv.addPending(clientKey.Public)
	if err != nil {
		t.Fatal(err)
	}

	loginRecorder := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodGet, "/login?request="+url.QueryEscape(requestID), nil)
	srv.Handler().ServeHTTP(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want %d: %s", loginRecorder.Code, http.StatusFound, loginRecorder.Body.String())
	}
	location, err := url.Parse(loginRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad redirect URL: %v", err)
	}
	state := location.Query().Get("state")
	cookies := loginRecorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("unexpected state cookie: %#v", cookies)
	}

	callbackRecorder := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=code&state="+url.QueryEscape(state), nil)
	callbackRequest.AddCookie(cookies[0])
	srv.Handler().ServeHTTP(callbackRecorder, callbackRequest)
	if callbackRecorder.Code != http.StatusOK {
		t.Fatalf("/callback status = %d, want %d: %s", callbackRecorder.Code, http.StatusOK, callbackRecorder.Body.String())
	}
	if strings.Contains(callbackRecorder.Body.String(), "tok") || strings.Contains(callbackRecorder.Body.String(), "HOP CERTIFICATE") {
		t.Fatalf("callback leaked a token or credential: %s", callbackRecorder.Body.String())
	}

	result := <-pending.result
	if result.Error != "" {
		t.Fatalf("enrollment failed: %s", result.Error)
	}
	credential, err := certs.ReadCertificatePEM([]byte(result.Certificate))
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if credential.PublicKey != clientKey.Public {
		t.Fatal("credential was issued for the wrong key")
	}
	if !credential.MatchesName(certs.RawStringName("testuser")) {
		t.Fatal("credential does not contain GitHub login")
	}
	validity := credential.ExpiresAt.Sub(credential.IssuedAt)
	if validity < time.Hour || validity > time.Hour+2*time.Second {
		t.Fatalf("credential validity = %s, want about 1h", validity)
	}
	if err := certs.VerifyParent(credential, srv.intermediateCert); err != nil {
		t.Fatalf("credential signature is invalid: %v", err)
	}
}

func TestGitHubFlowRejectsNonMember(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok","token_type":"bearer"}`)
	})
	ghMux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"outsider","id":4321,"type":"User"}`)
	})
	ghMux.HandleFunc("/user/memberships/orgs/testorg", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	githubServer := httptest.NewServer(ghMux)
	defer githubServer.Close()

	cfg := &config.Config{
		IntermediateCAPath:  "../intermediate.pem",
		IntermediateKeyPath: "../intermediate.key.pem",
		CertValidity:        time.Hour,
		RequestTimeout:      10 * time.Minute,
		PublicURL:           "https://vend.example",
		HopServerName:       "vend-server",
	}
	authenticator := NewGitHubAuthenticator(GitHubAuthenticatorConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  cfg.PublicURL + "/callback",
		APIBaseURL:   githubServer.URL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  githubServer.URL + "/auth",
			TokenURL: githubServer.URL + "/token",
		},
	})
	srv := NewWithAuth(cfg, authenticator, GitHubOrganizationAuthorizer{Organization: "testorg"})
	requestID, pending, err := srv.addPending(keys.GenerateNewX25519KeyPair().Public)
	if err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRecorder()
	srv.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?request="+requestID, nil))
	location, _ := url.Parse(login.Header().Get("Location"))
	state := location.Query().Get("state")
	callback := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/callback?code=code&state="+url.QueryEscape(state), nil)
	request.AddCookie(login.Result().Cookies()[0])
	srv.Handler().ServeHTTP(callback, request)

	if callback.Code != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403: %s", callback.Code, callback.Body.String())
	}
	result := <-pending.result
	if !strings.Contains(result.Error, "not an active member") {
		t.Fatalf("unexpected client error: %q", result.Error)
	}
}
