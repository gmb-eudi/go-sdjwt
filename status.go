package sdjwt

import (
	"encoding/json"
	"fmt"
	"math"
)

// extractStatus reads the status_list reference (IETF Token Status List §5)
// from the issuer payload. Absent → (nil, nil). Present but not the expected
// {status:{status_list:{idx,uri}}} shape → ErrStatusMalformed (fail closed;
// never silently ignored). Only the status_list mechanism is supported here;
// fetching/verifying the referenced list is go-statuslist (WP-04).
func extractStatus(payload map[string]any) (*StatusRef, error) {
	raw, ok := payload[claimStatus]
	if !ok {
		return nil, nil
	}
	st, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: status must be an object", ErrStatusMalformed)
	}
	slRaw, ok := st[claimStatusList]
	if !ok {
		return nil, fmt.Errorf("%w: status has no status_list", ErrStatusMalformed)
	}
	sl, ok := slRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: status_list must be an object", ErrStatusMalformed)
	}
	uri, ok := sl[claimURI].(string)
	if !ok || uri == "" {
		// M-4: this covers both an absent/wrong-type uri AND a present but
		// empty string ("") — the message says so explicitly rather than
		// reusing "missing" for the empty case (cosmetic; behavior unchanged).
		return nil, fmt.Errorf("%w: status_list.uri missing or empty", ErrStatusMalformed)
	}
	idx, ok := statusIndex(sl[claimIdx])
	if !ok {
		return nil, fmt.Errorf("%w: status_list.idx missing or invalid", ErrStatusMalformed)
	}
	return &StatusRef{URI: uri, Index: idx}, nil
}

// statusIndex coerces a non-negative integer idx. Every reader of a payload
// (Verify) reaches it via decodeJSONObject (json.Number); Issue always
// marshals its payload to JSON before signing, so a native Go int never
// reaches this function — only json.Number/float64 are handled.
func statusIndex(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0, false
		}
		return int(i), true
	case float64:
		if n < 0 || n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}
