package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	vendclient "hop.computer/vend/client"
	"hop.computer/vend/protocol"
	"hop.computer/vend/server/config"
)

const (
	testOIDCClientID     = "hop-vend-test"
	testOIDCClientSecret = "test-secret"
	testOIDCKeyID        = "test-signing-key"
)

type memoryOIDCProvider struct {
	server     *httptest.Server
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	mu    sync.Mutex
	codes map[string]string
}

func newMemoryOIDCProvider(t *testing.T) *memoryOIDCProvider {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &memoryOIDCProvider{
		publicKey:  publicKey,
		privateKey: privateKey,
		codes:      make(map[string]string),
	}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *memoryOIDCProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		p.writeJSON(w, map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/authorize",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		})
	case "/authorize":
		p.authorize(w, r)
	case "/token":
		p.token(w, r)
	case "/keys":
		p.writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "OKP",
				"crv": "Ed25519",
				"use": "sig",
				"alg": "EdDSA",
				"kid": testOIDCKeyID,
				"x":   base64.RawURLEncoding.EncodeToString(p.publicKey),
			}},
		})
	default:
		http.NotFound(w, r)
	}
}

func (p *memoryOIDCProvider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("client_id") != testOIDCClientID ||
		query.Get("response_type") != "code" ||
		query.Get("state") == "" ||
		query.Get("nonce") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	redirectURI, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || redirectURI.Scheme == "" || redirectURI.Host == "" {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	codeBytes := make([]byte, 24)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "unable to create code", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	p.mu.Lock()
	p.codes[code] = query.Get("nonce")
	p.mu.Unlock()

	callback := redirectURI.Query()
	callback.Set("code", code)
	callback.Set("state", query.Get("state"))
	redirectURI.RawQuery = callback.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (p *memoryOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	if clientID != testOIDCClientID || clientSecret != testOIDCClientSecret {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}
	code := r.Form.Get("code")
	p.mu.Lock()
	nonce, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	now := time.Now()
	idToken, err := p.signIDToken(map[string]any{
		"iss":                p.server.URL,
		"sub":                "subject-1234",
		"aud":                testOIDCClientID,
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"nonce":              nonce,
		"preferred_username": "oidc-user",
		"groups":             []string{"hop-users", "engineering"},
	})
	if err != nil {
		http.Error(w, "unable to sign ID token", http.StatusInternalServerError)
		return
	}
	p.writeJSON(w, map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (p *memoryOIDCProvider) signIDToken(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"kid": testOIDCKeyID,
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(p.privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *memoryOIDCProvider) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type loginURLWriter struct {
	urls chan string
}

func (w loginURLWriter) Write(data []byte) (int, error) {
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			select {
			case w.urls <- field:
			default:
			}
		}
	}
	return len(data), nil
}

func TestOIDCEndToEnd(t *testing.T) {
	identityProvider := newMemoryOIDCProvider(t)
	vendHTTP := httptest.NewUnstartedServer(nil)
	t.Cleanup(vendHTTP.Close)

	cfg := &config.Config{
		AuthProvider:        "oidc",
		OIDCIssuer:          identityProvider.server.URL,
		OIDCClientID:        testOIDCClientID,
		OIDCClientSecret:    testOIDCClientSecret,
		OIDCScopes:          []string{"openid", "profile"},
		OIDCIdentityClaim:   "preferred_username",
		AuthorizationClaim:  "groups",
		AuthorizationValue:  "hop-users",
		IntermediateCAPath:  "../intermediate.pem",
		IntermediateKeyPath: "../intermediate.key.pem",
		CertValidity:        time.Hour,
		RequestTimeout:      time.Minute,
		PublicURL:           "http://" + vendHTTP.Listener.Addr().String(),
		HopAddress:          "127.0.0.1:0",
		HopServerName:       "vend-server",
	}
	srv := New(cfg)
	vendHTTP.Config.Handler = srv.Handler()
	vendHTTP.Start()

	hopServer, err := srv.startHop()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := hopServer.Close(); err != nil {
			t.Errorf("close Hop server: %v", err)
		}
	})

	directory := t.TempDir()
	clientConfig := vendclient.Config{
		Address:          hopServer.Addr().String(),
		KeyPath:          filepath.Join(directory, "id_hop.pem"),
		CertificatePath:  filepath.Join(directory, "id_hop.cert"),
		IntermediatePath: filepath.Join(directory, "intermediate.cert"),
		RootCAPath:       "../root.pem",
		ServerName:       "vend-server",
		Timeout:          10 * time.Second,
	}
	loginURLs := make(chan string, 1)
	clientConfig.Output = loginURLWriter{urls: loginURLs}
	type enrollmentResult struct {
		credential *protocol.Credential
		err        error
	}
	enrollment := make(chan enrollmentResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		credential, err := vendclient.Enroll(ctx, clientConfig)
		enrollment <- enrollmentResult{credential: credential, err: err}
	}()

	var loginURL string
	select {
	case loginURL = <-loginURLs:
	case <-ctx.Done():
		t.Fatal("client did not receive a login URL")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	response, err := browser.Get(loginURL)
	if err != nil {
		t.Fatalf("complete browser authentication: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d: %s", response.StatusCode, body)
	}
	if strings.Contains(string(body), "test-access-token") ||
		strings.Contains(string(body), "HOP CERTIFICATE") {
		t.Fatalf("browser response leaked credential material: %s", body)
	}

	var result enrollmentResult
	select {
	case result = <-enrollment:
	case <-ctx.Done():
		t.Fatal("client did not receive an enrollment result")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.credential.Username != "oidc-user" {
		t.Fatalf("credential username = %q, want oidc-user", result.credential.Username)
	}
	if err := vendclient.Save(clientConfig, result.credential); err != nil {
		t.Fatal(err)
	}

	verifyOIDCCredential(t, clientConfig, result.credential)
}

func verifyOIDCCredential(
	t *testing.T,
	cfg vendclient.Config,
	credential *protocol.Credential,
) {
	t.Helper()
	leaf, err := certs.ReadCertificatePEM([]byte(credential.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := certs.ReadCertificatePEM([]byte(credential.Intermediate))
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.ReadDHKeyFromPEMFile(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PublicKey != key.Public {
		t.Fatal("credential is not bound to the enrollment key")
	}
	if !leaf.MatchesName(certs.RawStringName("oidc-user")) {
		t.Fatal("credential does not contain the OIDC identity")
	}
	if err := certs.VerifyParent(leaf, intermediate); err != nil {
		t.Fatalf("credential signature is invalid: %v", err)
	}
	if validity := leaf.ExpiresAt.Sub(leaf.IssuedAt); validity != time.Hour {
		t.Fatalf("credential validity = %s, want 1h", validity)
	}
	if credential.ExpiresAt.Unix() != leaf.ExpiresAt.Unix() {
		t.Fatal("credential expiry does not match the leaf certificate")
	}
	assertFileMode(t, cfg.KeyPath, 0o600)
	assertFileMode(t, cfg.CertificatePath, 0o644)
	assertFileMode(t, cfg.IntermediatePath, 0o644)
}

func assertFileMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("%s permissions = %o, want %o", path, actual, expected)
	}
}
