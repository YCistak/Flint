package blocklist

import "testing"

// TestLoadBaseline verifies the embedded baseline blocklist loads, is
// non-empty, and contains the expected Turkey + Russia baseline domains.
func TestLoadBaseline(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline() error: %v", err)
	}
	if bl.Len() == 0 {
		t.Fatal("baseline blocklist is empty")
	}

	// Representative entries from each region's baseline.
	want := []string{
		"discord.com", // Turkey
		"roblox.com",  // Turkey
		"facebook.com", // Russia
		"linkedin.com", // Russia
	}
	for _, d := range want {
		if !bl.Contains(d) {
			t.Errorf("baseline should contain %q but does not", d)
		}
	}
}

// TestContainsCaseInsensitive verifies matching ignores case and whitespace.
func TestContainsCaseInsensitive(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline() error: %v", err)
	}
	if !bl.Contains("  Discord.COM  ") {
		t.Error("Contains should normalise case and trim whitespace")
	}
	if bl.Contains("example.com") {
		t.Error("Contains returned true for a domain not in the list")
	}
}

// TestParseSkipsCommentsAndBlanks verifies the parser ignores comments and
// blank lines and counts only real domains.
func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	text := "# header comment\n\nexample.com\n   \n# another\nblocked.net\n"
	bl, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if bl.Len() != 2 {
		t.Fatalf("Parse() got %d domains, want 2 (%v)", bl.Len(), bl.Domains())
	}
}
