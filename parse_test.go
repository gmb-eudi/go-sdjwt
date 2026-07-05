package sdjwt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A syntactically valid compact JWS shell (3 base64url segments). Signature
// validity is irrelevant to the splitter — only structure is.
const jwtShell = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"
const kbShell = "eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6IngifQ.c2ln"

// base64url disclosures (no padding, no dots). Content need not decode here.
const d1 = "WyJzYWx0IiwibmFtZSIsInZhbHVlIl0"
const d2 = "WyJzYWx0MiIsImFnZSIsNDJd"

func TestSplitCombined(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantDiscs  int
		wantKB     bool
		wantSDPart string
	}{
		{"issuer only, no disclosures, no kb", jwtShell + "~", 0, false, jwtShell + "~"},
		{"two disclosures, no kb", jwtShell + "~" + d1 + "~" + d2 + "~", 2, false, jwtShell + "~" + d1 + "~" + d2 + "~"},
		{"two disclosures with kb", jwtShell + "~" + d1 + "~" + d2 + "~" + kbShell, 2, true, jwtShell + "~" + d1 + "~" + d2 + "~"},
		{"no disclosures with kb", jwtShell + "~" + kbShell, 0, true, jwtShell + "~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := splitCombined([]byte(tt.in))
			if err != nil {
				t.Fatalf("splitCombined: %v", err)
			}
			if len(p.disclosures) != tt.wantDiscs {
				t.Errorf("disclosures = %d, want %d", len(p.disclosures), tt.wantDiscs)
			}
			if (p.kb != nil) != tt.wantKB {
				t.Errorf("kb present = %v, want %v", p.kb != nil, tt.wantKB)
			}
			if string(p.sdPart) != tt.wantSDPart {
				t.Errorf("sdPart = %q, want %q", p.sdPart, tt.wantSDPart)
			}
			if !bytes.Equal(p.issuer, []byte(jwtShell)) {
				t.Errorf("issuer = %q", p.issuer)
			}
		})
	}
}

func TestSplitCombinedRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"no tilde at all", jwtShell, ErrMalformed},
		{"issuer not a JWS (missing dots)", "notajws~" + d1 + "~", ErrMalformed},
		{"empty issuer segment", "~" + d1 + "~", ErrMalformed},
		{"empty disclosure segment (double tilde)", jwtShell + "~~" + d1 + "~", ErrMalformed},
		{"trailing garbage in kb slot", jwtShell + "~" + d1 + "~garbage", ErrMalformed},
		{"disclosure contains a dot", jwtShell + "~a.b~", ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := splitCombined([]byte(tt.in)); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSplitCombinedSizeCap(t *testing.T) {
	big := jwtShell + "~" + strings.Repeat("A", maxPresentationBytes) + "~"
	if _, err := splitCombined([]byte(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestSplitCombinedCountCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(jwtShell)
	b.WriteByte('~')
	for i := 0; i < maxDisclosures+1; i++ {
		b.WriteString(d1)
		b.WriteByte('~')
	}
	if _, err := splitCombined([]byte(b.String())); !errors.Is(err, ErrDisclosureLimit) {
		t.Fatalf("err = %v, want ErrDisclosureLimit", err)
	}
}
