package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptAndDecryptAPIKey(t *testing.T) {
	encrypted, err := EncryptAPIKey("panel-secret", "test-secret")
	if err != nil {
		t.Fatalf("EncryptAPIKey() error = %v", err)
	}
	if !IsEncryptedAPIKey(encrypted) {
		t.Fatalf("EncryptAPIKey() = %q, want encrypted prefix", encrypted)
	}

	decrypted, err := DecryptAPIKey(encrypted, "test-secret")
	if err != nil {
		t.Fatalf("DecryptAPIKey() error = %v", err)
	}
	if decrypted != "panel-secret" {
		t.Fatalf("DecryptAPIKey() = %q, want %q", decrypted, "panel-secret")
	}
}

func TestResolveAPIKeySecretCreatesFile(t *testing.T) {
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "apikey.secret")

	secret, source, err := ResolveAPIKeySecret(secretFile, true)
	if err != nil {
		t.Fatalf("ResolveAPIKeySecret() error = %v", err)
	}
	if secret == "" {
		t.Fatal("ResolveAPIKeySecret() returned empty secret")
	}
	if source != secretFile {
		t.Fatalf("ResolveAPIKeySecret() source = %q, want %q", source, secretFile)
	}
	if _, err = os.Stat(secretFile); err != nil {
		t.Fatalf("ResolveAPIKeySecret() did not create secret file: %v", err)
	}
}
