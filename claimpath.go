package sdjwt

// ClaimPath identifies a selectively-disclosable claim in an SD-JWT for
// presentation (PresentKB). Elements are object keys (string) or array
// indices (non-negative int), mirroring the [OID4VP §7] claims path pointer
// JSON shape. It is defined locally so this format library stays independent
// of the protocol layer: go-dcql owns a parallel ClaimPath ([]PathElement)
// and the two are reconciled at the go-oid4vp boundary. go-sdjwt does
// NOT import go-dcql (layering: avoids a go-sdjwt->go-dcql dependency cycle).
type ClaimPath []any

// Path builds a ClaimPath from string keys and int indices.
func Path(elems ...any) ClaimPath { return ClaimPath(elems) }

// valid reports whether every element is a string key or a non-negative int
// index, and the path is non-empty ([OID4VP §7]).
func (p ClaimPath) valid() bool {
	if len(p) == 0 {
		return false
	}
	for _, e := range p {
		switch v := e.(type) {
		case string:
		case int:
			if v < 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// equal reports element-wise equality.
func (p ClaimPath) equal(o ClaimPath) bool {
	if len(p) != len(o) {
		return false
	}
	for i := range p {
		if p[i] != o[i] {
			return false
		}
	}
	return true
}

// prefixOf reports whether p is a (non-strict) prefix of o.
func (p ClaimPath) prefixOf(o ClaimPath) bool {
	if len(p) > len(o) {
		return false
	}
	for i := range p {
		if p[i] != o[i] {
			return false
		}
	}
	return true
}
