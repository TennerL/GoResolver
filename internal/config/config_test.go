package config

import "testing"

func TestRequiredSecret(t *testing.T) {
	t.Setenv("GORESOLVER_TEST_SECRET", "  secret-value  ")

	secret, err := RequiredSecret("GORESOLVER_TEST_SECRET")
	if err != nil {
		t.Fatalf("RequiredSecret() error = %v", err)
	}
	if string(secret) != "secret-value" {
		t.Fatalf("RequiredSecret() = %q, want %q", secret, "secret-value")
	}
}

func TestRequiredSecretMissing(t *testing.T) {
	if _, err := RequiredSecret("GORESOLVER_DOES_NOT_EXIST"); err == nil {
		t.Fatal("RequiredSecret() should fail for missing values")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	first, err := DeriveKey([]byte("same-secret"), "purpose", 32)
	if err != nil {
		t.Fatalf("DeriveKey() first call error = %v", err)
	}
	second, err := DeriveKey([]byte("same-secret"), "purpose", 32)
	if err != nil {
		t.Fatalf("DeriveKey() second call error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("DeriveKey() should be deterministic for identical inputs")
	}
}
