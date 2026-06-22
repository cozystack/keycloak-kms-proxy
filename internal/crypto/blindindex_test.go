package crypto

import "testing"

func TestBlindIndexDeterministic(t *testing.T) {
	t.Parallel()

	key, err := GenerateBlindIndexKey()
	if err != nil {
		t.Fatalf("GenerateBlindIndexKey: %v", err)
	}
	bi := NewBlindIndex(key)
	aad := []byte("USER_ENTITY.EMAIL")

	a, err := bi.Compute([]byte("alice@example.com"), aad)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	b, err := bi.Compute([]byte("alice@example.com"), aad)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if a != b {
		t.Fatalf("blind index not deterministic for equal input+aad: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("hex length: got %d, want 64", len(a))
	}
}

func TestBlindIndexDistinctOnAADAndPlaintext(t *testing.T) {
	t.Parallel()

	key, _ := GenerateBlindIndexKey()
	bi := NewBlindIndex(key)

	emailAlice, _ := bi.Compute([]byte("alice@example.com"), []byte("USER_ENTITY.EMAIL"))
	emailBob, _ := bi.Compute([]byte("bob@example.com"), []byte("USER_ENTITY.EMAIL"))
	if emailAlice == emailBob {
		t.Error("distinct plaintexts hashed to the same value")
	}

	usernameAlice, _ := bi.Compute([]byte("alice@example.com"), []byte("USER_ENTITY.USERNAME"))
	if emailAlice == usernameAlice {
		t.Error("same plaintext under different AAD hashed to the same value")
	}
}

func TestBlindIndexDifferentKey(t *testing.T) {
	t.Parallel()

	k1, _ := GenerateBlindIndexKey()
	k2, _ := GenerateBlindIndexKey()
	a, _ := NewBlindIndex(k1).Compute([]byte("alice"), []byte("aad"))
	b, _ := NewBlindIndex(k2).Compute([]byte("alice"), []byte("aad"))
	if a == b {
		t.Error("different keys produced the same hash")
	}
}
