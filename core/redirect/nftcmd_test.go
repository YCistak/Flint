package redirect

import (
	"strings"
	"testing"
)

// These tests lock the intended nft rule syntax. They do not run nft (that needs
// root and is validated live); they guard against accidental syntax drift.

func TestNftChainIsNatOutput(t *testing.T) {
	got := strings.Join(nftAddChainArgs(), " ")
	want := "add chain ip flint_redirect output { type nat hook output priority -100 ; policy accept ; }"
	if got != want {
		t.Fatalf("chain args:\n got: %s\nwant: %s", got, want)
	}
}

func TestNftRuleRedirectsMonitoredPorts(t *testing.T) {
	got := strings.Join(nftAddRuleArgs(1090), " ")
	want := "add rule ip flint_redirect output ip daddr @blocked tcp dport { 80, 443 } redirect to :1090"
	if got != want {
		t.Fatalf("rule args:\n got: %s\nwant: %s", got, want)
	}
}

func TestNftElementAddDelete(t *testing.T) {
	if got := strings.Join(nftAddElementArgs("1.2.3.4"), " "); got != "add element ip flint_redirect blocked { 1.2.3.4 }" {
		t.Fatalf("add element: %s", got)
	}
	if got := strings.Join(nftDeleteElementArgs("1.2.3.4"), " "); got != "delete element ip flint_redirect blocked { 1.2.3.4 }" {
		t.Fatalf("delete element: %s", got)
	}
}

func TestNftTableTeardownIsSingleDelete(t *testing.T) {
	if got := strings.Join(nftDeleteTableArgs(), " "); got != "delete table ip flint_redirect" {
		t.Fatalf("delete table: %s", got)
	}
}
