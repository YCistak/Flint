// Package blocklist loads the bundled list of known-blocked domains. The
// baseline list is embedded in the binary so Flint can pre-seed its detection
// cache and skip cold-start probing for common cases (see PLANNED.md).
package blocklist

import (
	"bufio"
	_ "embed"
	"strings"
)

//go:embed data/baseline.txt
var baselineData string

// Blocklist is a case-insensitive set of blocked domains.
type Blocklist struct {
	domains map[string]struct{}
}

// LoadBaseline parses the embedded baseline blocklist that ships with Flint.
func LoadBaseline() (*Blocklist, error) {
	return Parse(baselineData)
}

// Parse builds a Blocklist from newline-separated text. Blank lines and lines
// beginning with '#' are ignored; domains are normalised to lowercase.
func Parse(text string) (*Blocklist, error) {
	bl := &Blocklist{domains: make(map[string]struct{})}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		bl.domains[strings.ToLower(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return bl, nil
}

// Contains reports whether domain is in the blocklist (case-insensitive).
func (b *Blocklist) Contains(domain string) bool {
	_, ok := b.domains[strings.ToLower(strings.TrimSpace(domain))]
	return ok
}

// Len returns the number of domains in the blocklist.
func (b *Blocklist) Len() int { return len(b.domains) }

// Domains returns the blocked domains. Order is unspecified.
func (b *Blocklist) Domains() []string {
	out := make([]string, 0, len(b.domains))
	for d := range b.domains {
		out = append(out, d)
	}
	return out
}
