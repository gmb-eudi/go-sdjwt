package sdjwt

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

var errPresentNoDecrypter = errors.New("sdjwt: holder signer provider is sign-only")

// PresentKB builds a holder presentation of an issued SD-JWT: it selects the
// disclosures required for the disclose paths, appends a Key-Binding JWT
// (kb+jwt) signed by holder over the exact presented issuer-JWT+disclosures
// (SD-JWT §4.3). The issuer signature is NOT re-verified here (the holder
// presents its own, already-trusted credential — see WP-02 README
// Decisions). now is injected (no wall clock). Reused by the future issuer
// and internal/testwallet.
func PresentKB(ctx context.Context, holder stdcrypto.Signer, sdJWT []byte, disclose []ClaimPath, aud, nonce string, now time.Time) ([]byte, error) {
	for _, p := range disclose {
		if !p.valid() {
			return nil, fmt.Errorf("%w: invalid disclose path", ErrClaimPath)
		}
	}
	p, err := splitCombined(sdJWT)
	if err != nil {
		return nil, err
	}
	payload, err := issuerPayloadUnverified(p.issuer)
	if err != nil {
		return nil, err
	}
	h, err := hashForSDAlg(eudicrypto.ECCG(), payload)
	if err != nil {
		return nil, err
	}
	selected, err := selectDisclosures(payload, p.disclosures, disclose, h)
	if err != nil {
		return nil, err
	}

	// sdPart = <issuer>~<selected disclosures>~ (exact sd_hash input).
	sdPart := append([]byte{}, p.issuer...)
	sdPart = append(sdPart, '~')
	for _, d := range selected {
		sdPart = append(sdPart, d...)
		sdPart = append(sdPart, '~')
	}

	kbBody := map[string]any{
		claimIAT:    now.Unix(),
		claimAUD:    aud,
		claimNonce:  nonce,
		claimSDHash: digest(sdPart, h),
	}
	raw, err := json.Marshal(kbBody)
	if err != nil {
		return nil, fmt.Errorf("%w: kb body: %v", ErrMalformed, err)
	}
	kb, err := eudicrypto.SignJWS(ctx, signerProvider{holder}, "", map[string]any{hdrTyp: typKB}, raw)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte{}, sdPart...), kb...)
	return out, nil
}

// issuerPayloadUnverified base64url-decodes the payload segment of a compact
// JWS without verifying the signature (holder-side path only — the holder
// trusts a credential it already holds).
func issuerPayloadUnverified(issuer []byte) (map[string]any, error) {
	parts := bytes.Split(issuer, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: issuer not a compact JWS", ErrMalformed)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("%w: issuer payload: %v", ErrMalformed, err)
	}
	return decodeJSONObject(raw)
}

// selectDisclosures returns the disclosures (in issued order) needed to
// present the requested paths. A disclosure at path dp is kept iff, for some
// requested path w: dp is a prefix of w (an ancestor needed to reach w) OR w
// is a prefix of dp (w itself and its whole subtree — selecting a container
// discloses everything under it). Every requested path must name an existing
// node in the fully-disclosed structure, or ErrClaimPath (path only, never a
// value — hard rule 3).
//
// Pinned behavior (M-3): a requested path that names an existing node which
// was never made selective (an always-clear claim — no _sd digest/"..."
// wrapper references it, so it has no entry in s.discPath) passes the
// existence check but matches nothing in the keep-set loop below — it is a
// no-op, not an error. This is not a bug: the claim is already present in
// the clear regardless of what PresentKB selects, so there is nothing to add
// to the disclosure set for it. See TestPresentKBNonSelectiveExistingPathIsNoop.
func selectDisclosures(payload map[string]any, discs [][]byte, want []ClaimPath, h stdcrypto.Hash) ([][]byte, error) {
	s := &selector{byDigest: map[string]disclosure{}, discPath: map[string]ClaimPath{}}
	for _, raw := range discs {
		d, err := decodeDisclosure(raw)
		if err != nil {
			return nil, err
		}
		s.byDigest[digest(raw, h)] = d
	}
	s.walkVal(payload, ClaimPath{})

	// Existence: each requested path must equal some real node in the
	// disclosed structure.
	for _, w := range want {
		found := false
		for _, r := range s.nodePaths {
			if w.equal(r) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrClaimPath, pathKey(w))
		}
	}
	// Keep set: ancestors needed to reach a request, plus a requested node's
	// own subtree.
	keep := map[string]bool{}
	for dg, dp := range s.discPath {
		for _, w := range want {
			if dp.prefixOf(w) || w.prefixOf(dp) {
				keep[dg] = true
				break
			}
		}
	}
	out := make([][]byte, 0, len(discs))
	for _, raw := range discs {
		if keep[digest(raw, h)] {
			out = append(out, raw)
		}
	}
	return out, nil
}

// selector walks the fully-disclosed structure (resolving every _sd digest /
// "..." wrapper against the presentation's own disclosure set) recording
// every node path and, for each disclosure, the path it occupies.
type selector struct {
	byDigest  map[string]disclosure
	discPath  map[string]ClaimPath
	nodePaths []ClaimPath
}

func (s *selector) walkVal(v any, path ClaimPath) {
	s.nodePaths = append(s.nodePaths, path)
	switch t := v.(type) {
	case map[string]any:
		s.walkObj(t, path)
	case []any:
		s.walkArr(t, path)
	}
}

func (s *selector) walkObj(m map[string]any, path ClaimPath) {
	for k, v := range m {
		if k == claimSD || k == claimSDAlg {
			continue
		}
		s.walkVal(v, appendPath(path, k))
	}
	sd, ok := m[claimSD].([]any)
	if !ok {
		return
	}
	for _, e := range sd {
		dg, ok := e.(string)
		if !ok {
			continue
		}
		d, found := s.byDigest[dg]
		if !found || len(d.arr) != 3 {
			continue
		}
		name, ok := d.arr[1].(string)
		if !ok {
			continue
		}
		cp := appendPath(path, name)
		s.discPath[dg] = cp
		s.walkVal(d.arr[2], cp)
	}
}

func (s *selector) walkArr(a []any, path ClaimPath) {
	for i, e := range a {
		cp := appendPath(path, i)
		if dg, ok := arrayDigest(e); ok {
			d, found := s.byDigest[dg]
			if !found || len(d.arr) != 2 {
				continue
			}
			s.discPath[dg] = cp
			s.walkVal(d.arr[1], cp)
			continue
		}
		s.walkVal(e, cp)
	}
}

// signerProvider adapts a single crypto.Signer to eudicrypto.KeyProvider so
// PresentKB can drive crypto.SignJWS for the KB-JWT with the holder's own
// key. Sign-only: Decrypter always fails (KB-JWTs are never JWE).
type signerProvider struct{ s stdcrypto.Signer }

func (p signerProvider) Signer(context.Context, string) (stdcrypto.Signer, error) { return p.s, nil }
func (p signerProvider) Decrypter(context.Context, string) (eudicrypto.Decrypter, error) {
	return nil, errPresentNoDecrypter
}
func (p signerProvider) Public(context.Context, string) (stdcrypto.PublicKey, error) {
	return p.s.Public(), nil
}
