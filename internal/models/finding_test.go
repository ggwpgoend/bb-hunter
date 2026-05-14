package models

import (
	"testing"
)

func TestComputeFindingKey_Deterministic(t *testing.T) {
	key1 := ComputeFindingKey("GET", "https://example.com/api/users?id=1", "http-missing-security-headers", []string{"id"})
	key2 := ComputeFindingKey("GET", "https://example.com/api/users?id=1", "http-missing-security-headers", []string{"id"})

	if key1 != key2 {
		t.Errorf("same input should produce same key: %s != %s", key1, key2)
	}
}

func TestComputeFindingKey_MethodMatters(t *testing.T) {
	keyGet := ComputeFindingKey("GET", "https://example.com/api", "tpl", nil)
	keyPost := ComputeFindingKey("POST", "https://example.com/api", "tpl", nil)

	if keyGet == keyPost {
		t.Error("different methods should produce different keys")
	}
}

func TestComputeFindingKey_ParamOrderInsensitive(t *testing.T) {
	key1 := ComputeFindingKey("GET", "https://example.com/search", "tpl", []string{"q", "page", "lang"})
	key2 := ComputeFindingKey("GET", "https://example.com/search", "tpl", []string{"lang", "page", "q"})

	if key1 != key2 {
		t.Errorf("param order should not matter: %s != %s", key1, key2)
	}
}

func TestComputeFindingKey_NormalizesHost(t *testing.T) {
	key1 := ComputeFindingKey("GET", "https://EXAMPLE.COM/path", "tpl", nil)
	key2 := ComputeFindingKey("GET", "https://example.com/path", "tpl", nil)

	if key1 != key2 {
		t.Errorf("host case should not matter: %s != %s", key1, key2)
	}
}

func TestComputeFindingKey_NormalizesTrailingSlash(t *testing.T) {
	key1 := ComputeFindingKey("GET", "https://example.com/api/users/", "tpl", nil)
	key2 := ComputeFindingKey("GET", "https://example.com/api/users", "tpl", nil)

	if key1 != key2 {
		t.Errorf("trailing slash should not matter: %s != %s", key1, key2)
	}
}

func TestComputeFindingKey_RootPathPreserved(t *testing.T) {
	key := ComputeFindingKey("GET", "https://example.com/", "tpl", nil)
	if key == "" {
		t.Error("root path should produce a valid key")
	}
}

func TestComputeFindingKey_DifferentTemplates(t *testing.T) {
	key1 := ComputeFindingKey("GET", "https://example.com/", "xss-reflected", nil)
	key2 := ComputeFindingKey("GET", "https://example.com/", "sqli-blind", nil)

	if key1 == key2 {
		t.Error("different templates should produce different keys")
	}
}

func TestComputeFindingKey_NoStatusCode(t *testing.T) {
	// The key should NOT include status code (per v4 critique §2.5 — status codes flap)
	// This is verified by the fact that ComputeFindingKey doesn't accept status_code param.
	// This test documents the design decision.
	key := ComputeFindingKey("GET", "https://example.com/api", "tpl", []string{"id"})
	if len(key) != 32 { // 16 bytes hex = 32 chars
		t.Errorf("expected 32-char hex key, got %d chars: %s", len(key), key)
	}
}
