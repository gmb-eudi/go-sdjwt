package sdjwt

import (
	"bytes"
	stdcrypto "crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// disclosure is a decoded SD-JWT Disclosure: [salt, name, value] for an
// object property (len 3) or [salt, value] for an array element (len 2)
// ([SD-JWT §4.2]).
type disclosure struct {
	raw []byte // the base64url string, hashed as-is ([SD-JWT §4.2.1])
	arr []any  // decoded array
}

// decodeDisclosure base64url-decodes and JSON-parses one Disclosure. Numbers
// are preserved as json.Number. It validates shape (2 or 3 elements, string
// salt) but not semantics.
func decodeDisclosure(raw []byte) (disclosure, error) {
	dec, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil {
		return disclosure{}, fmt.Errorf("%w: base64url: %v", ErrDisclosure, err)
	}
	var arr []any
	d := json.NewDecoder(bytes.NewReader(dec))
	d.UseNumber()
	if err := d.Decode(&arr); err != nil {
		// Static suffix only: a *json.SyntaxError's message can echo a byte of
		// the decoded disclosure content ([salt, name, value]) — never wrap
		// the underlying err (no attribute values in errors — GDPR).
		return disclosure{}, fmt.Errorf("%w: disclosure is not valid JSON", ErrDisclosure)
	}
	if d.More() {
		return disclosure{}, fmt.Errorf("%w: trailing data in disclosure", ErrDisclosure)
	}
	if len(arr) != 2 && len(arr) != 3 {
		return disclosure{}, fmt.Errorf("%w: disclosure must have 2 or 3 elements", ErrDisclosure)
	}
	if _, ok := arr[0].(string); !ok {
		return disclosure{}, fmt.Errorf("%w: disclosure salt must be a string", ErrDisclosure)
	}
	return disclosure{raw: raw, arr: arr}, nil
}

// digest computes the SD-JWT digest of a disclosure: base64url(h(ASCII(raw)))
// where raw is the base64url disclosure string itself ([SD-JWT §4.2.1]).
func digest(raw []byte, h stdcrypto.Hash) string {
	hh := h.New()
	hh.Write(raw)
	return base64.RawURLEncoding.EncodeToString(hh.Sum(nil))
}

// hashForSDAlg resolves the payload _sd_alg ([SD-JWT §4.1.1]) to a crypto.Hash
// via the ECCG policy. Absent → policy default (sha-256). Unknown or
// non-string → ErrHashAlg (fail closed; no hard-coded algorithm literal here).
func hashForSDAlg(pol eudicrypto.Policy, payload map[string]any) (stdcrypto.Hash, error) {
	name := ""
	if v, ok := payload[claimSDAlg]; ok {
		s, ok := v.(string)
		if !ok {
			return 0, fmt.Errorf("%w: _sd_alg must be a string", ErrHashAlg)
		}
		name = s
	}
	h, err := pol.HashForName(name)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrHashAlg, err)
	}
	return h, nil
}
