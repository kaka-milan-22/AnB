package crypto

import (
	"encoding/json"
	"strings"
	"testing"
)

// v2.5 and earlier wrote the envelope as a bare single-key JSON object.
// v2.6 LoadEnvelopeFile must migrate that shape into the v3 in-memory
// form without rewriting the disk file (rewriting happens on the next
// rotate-* call).
func TestLoadEnvelopeFile_LegacyV2Migration(t *testing.T) {
	mk, _ := NewMasterKey()
	env, err := Wrap(mk, "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Serialize as a bare Envelope (v2 shape).
	legacy, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), `"keys"`) {
		t.Fatalf("legacy fixture leaked a keys[] field: %s", legacy)
	}

	f, err := LoadEnvelopeFile(legacy)
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if f.Current != 1 || len(f.Keys) != 1 || f.Keys[0].ID != 1 {
		t.Fatalf("expected single-key v3 with current=1, got %+v", f)
	}
	// Round-trip: unwrap that key with the password we used.
	got, err := Unwrap(&f.Keys[0], "pw")
	if err != nil {
		t.Fatalf("unwrap migrated key: %v", err)
	}
	if string(got) != string(mk) {
		t.Fatal("unwrapped K mismatch")
	}
}

// v3 envelope round-trip: marshal → unmarshal preserves keys, ids, current.
func TestEnvelopeFileRoundTrip(t *testing.T) {
	k1, _ := NewMasterKey()
	k2, _ := NewMasterKey()
	e1, _ := Wrap(k1, "pw")
	e1.ID = 1
	e1.Created = "2026-05-27T00:00:00Z"
	e2, _ := Wrap(k2, "pw")
	e2.ID = 2
	e2.Created = "2026-05-29T00:00:00Z"
	src := &EnvelopeFile{Keys: []Envelope{*e1, *e2}, Current: 2}

	body, err := MarshalEnvelopeFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"version": 3`) {
		t.Fatalf("v3 marshal missing version field: %s", body)
	}

	got, err := LoadEnvelopeFile(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != 2 || len(got.Keys) != 2 {
		t.Fatalf("round-trip lost structure: %+v", got)
	}
	if got.FindKey(1) == nil || got.FindKey(2) == nil {
		t.Fatalf("FindKey missed entries: %+v", got)
	}
	if got.NextID() != 3 {
		t.Fatalf("NextID = %d, want 3", got.NextID())
	}
}

func TestEnvelopeFile_RemoveKey_RefusesCurrent(t *testing.T) {
	mk, _ := NewMasterKey()
	e, _ := Wrap(mk, "pw")
	e.ID = 1
	f := &EnvelopeFile{Keys: []Envelope{*e}, Current: 1}
	if err := f.RemoveKey(1); err == nil {
		t.Fatal("expected refusal removing current key")
	}
}

func TestEnvelopeFile_RemoveKey_OK(t *testing.T) {
	k1, _ := NewMasterKey()
	k2, _ := NewMasterKey()
	e1, _ := Wrap(k1, "pw")
	e1.ID = 1
	e2, _ := Wrap(k2, "pw")
	e2.ID = 2
	f := &EnvelopeFile{Keys: []Envelope{*e1, *e2}, Current: 2}
	if err := f.RemoveKey(1); err != nil {
		t.Fatal(err)
	}
	if len(f.Keys) != 1 || f.Keys[0].ID != 2 {
		t.Fatalf("post-remove: %+v", f.Keys)
	}
}

// ParseVersion / PackVersion edge cases.
func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		wantV   int
		wantRaw string
		wantErr bool
	}{
		{"v1:iv:tag:ct", 1, "iv:tag:ct", false},
		{"v2:abc:def:ghi", 2, "abc:def:ghi", false},
		{"v999:x:y:z", 999, "x:y:z", false},
		{"iv:tag:ct", 1, "iv:tag:ct", false}, // legacy v1 (no prefix)
		{"", 0, "", true},
		{"v0:x:y:z", 0, "", true},              // version 0 rejected
		{"vfoo:x:y:z", 1, "vfoo:x:y:z", false}, // 'foo' isn't digits → no match → fallback v1
	}
	for _, c := range cases {
		v, raw, err := ParseVersion(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%q): want error, got (%d, %q)", c.in, v, raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%q): %v", c.in, err)
			continue
		}
		if v != c.wantV || raw != c.wantRaw {
			t.Errorf("ParseVersion(%q) = (%d, %q), want (%d, %q)", c.in, v, raw, c.wantV, c.wantRaw)
		}
	}
}

func TestPackVersionRoundTrip(t *testing.T) {
	for _, v := range []int{1, 2, 7, 1000} {
		packed := PackVersion(v, "iv:tag:ct")
		gotV, gotRaw, err := ParseVersion(packed)
		if err != nil {
			t.Fatal(err)
		}
		if gotV != v || gotRaw != "iv:tag:ct" {
			t.Fatalf("v=%d round-trip: got (%d, %q)", v, gotV, gotRaw)
		}
	}
}
