package services

import "testing"

func TestEncryptDecryptVPN(t *testing.T) {
	t.Setenv("GORESOLVER_VPN_ENCRYPTION_SECRET", "current-secret")

	ciphertext, err := EncryptVPN([]byte("vpn-config"))
	if err != nil {
		t.Fatalf("EncryptVPN() error = %v", err)
	}

	plaintext, err := DecryptVPN(ciphertext)
	if err != nil {
		t.Fatalf("DecryptVPN() error = %v", err)
	}
	if string(plaintext) != "vpn-config" {
		t.Fatalf("DecryptVPN() = %q, want %q", plaintext, "vpn-config")
	}
}

func TestDecryptVPNSupportsPreviousSecret(t *testing.T) {
	t.Setenv("GORESOLVER_VPN_ENCRYPTION_SECRET", "old-secret")
	ciphertext, err := EncryptVPN([]byte("vpn-config"))
	if err != nil {
		t.Fatalf("EncryptVPN() error = %v", err)
	}

	t.Setenv("GORESOLVER_VPN_ENCRYPTION_SECRET", "new-secret")
	t.Setenv("GORESOLVER_VPN_ENCRYPTION_SECRET_PREVIOUS", "old-secret")

	plaintext, err := DecryptVPN(ciphertext)
	if err != nil {
		t.Fatalf("DecryptVPN() with previous secret error = %v", err)
	}
	if string(plaintext) != "vpn-config" {
		t.Fatalf("DecryptVPN() = %q, want %q", plaintext, "vpn-config")
	}
}
