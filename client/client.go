// Package client implements the Hop Vend enrollment client.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
	"hop.computer/vend/protocol"
)

// Config controls enrollment and local credential storage.
type Config struct {
	Address          string
	KeyPath          string
	CertificatePath  string
	IntermediatePath string
	RootCAPath       string
	ServerName       string
	Insecure         bool
	Timeout          time.Duration
	Output           io.Writer
}

// Enroll connects to Hop Vend and waits for the browser authorization flow.
func Enroll(ctx context.Context, cfg Config) (*protocol.Credential, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.Output == nil {
		cfg.Output = io.Discard
	}
	key, err := ensureKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	selfSigned, err := certs.SelfSignLeaf(certs.LeafIdentity(key, certs.RawStringName("hop-vend-enrollment")))
	if err != nil {
		return nil, fmt.Errorf("create enrollment identity: %w", err)
	}

	verify := transport.VerifyConfig{InsecureSkipVerify: cfg.Insecure}
	var roots *certs.Store
	if !cfg.Insecure {
		if cfg.RootCAPath == "" {
			return nil, errors.New("a root CA file is required unless -insecure is used")
		}
		roots, err = loadRootStore(cfg.RootCAPath, time.Now())
		if err != nil {
			return nil, fmt.Errorf("load root CA: %w", err)
		}
		verify.Store = *roots
		verify.Name = certs.RawStringName(cfg.ServerName)
	}
	conn, err := transport.Dial("udp", cfg.Address, transport.ClientConfig{
		Exchanger: key,
		Leaf:      selfSigned,
		HSTimeout: minDuration(cfg.Timeout, 15*time.Second),
		Verify:    verify,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to Hop Vend: %w", err)
	}
	defer conn.Close()
	stopCancellation := make(chan struct{})
	defer close(stopCancellation)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopCancellation:
		}
	}()
	deadline := time.Now().Add(cfg.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set enrollment deadline: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var login protocol.Login
	if err := decoder.Decode(&login); err != nil {
		return nil, fmt.Errorf("read login URL: %w", err)
	}
	if login.LoginURL == "" {
		return nil, errors.New("server returned an empty login URL")
	}
	fmt.Fprintf(cfg.Output, "Open this URL to authenticate with GitHub:\n%s\n\nWaiting for authorization...\n", login.LoginURL)

	var credential protocol.Credential
	if err := decoder.Decode(&credential); err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	if credential.Error != "" {
		return nil, errors.New(credential.Error)
	}
	if err := validateCredential(&credential, key, roots, cfg.Insecure); err != nil {
		return nil, err
	}
	return &credential, nil
}

// Save writes a successful enrollment result to the configured paths.
func Save(cfg Config, credential *protocol.Credential) error {
	if credential == nil || credential.Certificate == "" || credential.Intermediate == "" {
		return errors.New("credential response is incomplete")
	}
	if err := atomicWrite(cfg.CertificatePath, []byte(credential.Certificate), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := atomicWrite(cfg.IntermediatePath, []byte(credential.Intermediate), 0o644); err != nil {
		return fmt.Errorf("write intermediate certificate: %w", err)
	}
	return nil
}

func ensureKey(path string) (*keys.X25519KeyPair, error) {
	key, err := keys.ReadDHKeyFromPEMFile(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read Hop key: %w", err)
	}
	key = keys.GenerateNewX25519KeyPair()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create Hop configuration directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create Hop key: %w", err)
	}
	if err := keys.EncodeDHKeyToPEM(file, key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("encode Hop key: %w", err)
	}
	if _, err := file.Write([]byte{'\n'}); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("finish Hop key: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close Hop key: %w", err)
	}
	return key, nil
}

func validateCredential(
	credential *protocol.Credential,
	key *keys.X25519KeyPair,
	roots *certs.Store,
	insecure bool,
) error {
	leaf, err := certs.ReadCertificatePEM([]byte(credential.Certificate))
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	intermediate, err := certs.ReadCertificatePEM([]byte(credential.Intermediate))
	if err != nil {
		return fmt.Errorf("parse intermediate certificate: %w", err)
	}
	if leaf.PublicKey != key.Public {
		return errors.New("issued certificate is for a different key")
	}
	if credential.Username == "" || !leaf.MatchesName(certs.RawStringName(credential.Username)) {
		return errors.New("issued certificate does not contain the authenticated GitHub username")
	}
	now := time.Now()
	if leaf.IssuedAt.After(now.Add(time.Minute)) || !leaf.ExpiresAt.After(now) {
		return errors.New("issued certificate is not currently valid")
	}
	if intermediate.IssuedAt.After(now.Add(time.Minute)) || !intermediate.ExpiresAt.After(now) {
		return errors.New("issuing intermediate certificate is not currently valid")
	}
	if credential.ExpiresAt.Unix() != leaf.ExpiresAt.Unix() {
		return errors.New("credential expiry does not match the certificate")
	}
	if !insecure {
		if roots == nil {
			return errors.New("root certificate store is missing")
		}
		if err := roots.VerifyLeaf(leaf, certs.VerifyOptions{
			PresentedIntermediate: intermediate,
			Name:                  certs.RawStringName(credential.Username),
		}); err != nil {
			return fmt.Errorf("verify issued certificate: %w", err)
		}
	}
	return nil
}

func loadRootStore(path string, now time.Time) (*certs.Store, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	certificates, err := certs.ReadManyCertificatesPEM(file)
	if err != nil {
		return nil, err
	}
	store := new(certs.Store)
	validRoots := 0
	for i := range certificates {
		certificate := &certificates[i]
		store.AddCertificate(certificate)
		if certificate.Type == certs.Root &&
			!now.Before(certificate.IssuedAt) &&
			now.Before(certificate.ExpiresAt) {
			validRoots++
		}
	}
	if validRoots == 0 {
		return nil, errors.New("root CA file contains no currently valid Hop root certificate")
	}
	return store, nil
}

func atomicWrite(path string, contents []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("output path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".hop-vend-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
