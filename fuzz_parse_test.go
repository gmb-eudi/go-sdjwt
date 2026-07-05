package sdjwt

import "testing"

// Hard rule 5: splitCombined must never panic on malformed input.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"~",
		jwtShell + "~",
		jwtShell + "~" + d1 + "~",
		jwtShell + "~" + d1 + "~" + d2 + "~" + kbShell,
		jwtShell + "~~" + d1 + "~",
		"notajws~" + d1 + "~",
		jwtShell + "~" + d1 + "~garbage",
		"~~~~~",
		jwtShell + "~a.b.c~",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		p, err := splitCombined(data)
		if err != nil {
			return
		}
		// Invariants on any accepted parse.
		if !isCompactJWS(p.issuer) {
			panic("accepted a non-JWS issuer")
		}
		if len(p.sdPart) > len(data) {
			panic("sdPart longer than input")
		}
		for _, d := range p.disclosures {
			if len(d) == 0 {
				panic("accepted an empty disclosure")
			}
		}
	})
}
