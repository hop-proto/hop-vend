package client

import (
	"os"
	"path/filepath"
	"testing"

	"hop.computer/vend/protocol"
)

func TestEnsureKeyAndSave(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "nested", "id_hop.pem")
	first, err := ensureKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ensureKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.Private != second.Private || first.Public != second.Public {
		t.Fatal("ensureKey did not reuse the existing key")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}

	cfg := Config{
		CertificatePath:  filepath.Join(directory, "id_hop.cert"),
		IntermediatePath: filepath.Join(directory, "intermediate.cert"),
	}
	credential := &protocol.Credential{
		Certificate:  "leaf\n",
		Intermediate: "intermediate\n",
	}
	if err := Save(cfg, credential); err != nil {
		t.Fatal(err)
	}
	leaf, err := os.ReadFile(cfg.CertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := os.ReadFile(cfg.IntermediatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(leaf) != credential.Certificate || string(intermediate) != credential.Intermediate {
		t.Fatal("saved credential contents do not match")
	}
}
