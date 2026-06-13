package redirect

import (
	"fmt"
	"strconv"
	"strings"
)

// nft command builders, separated from execution so the exact rule syntax is
// unit-testable on any platform. The redirect path lives in a dedicated table
// (redirectTable) so teardown is a single `delete table` that never touches the
// user's other firewall rules or the DPI engine's `flint_dpi` table.
//
// Layout installed by these commands:
//
//	table ip flint_redirect {
//	    set blocked { type ipv4_addr }          # destinations the detector flagged
//	    chain output {                          # nat/output: DNAT before routing
//	        type nat hook output priority -100;
//	        ip daddr @blocked tcp dport {80,443} redirect to :<toPort>
//	    }
//	}
const (
	redirectTable = "flint_redirect"
	redirectSet   = "blocked"
	redirectChain = "output"
)

// redirectPorts are the destination ports diverted to the transparent proxy.
var redirectPorts = []int{80, 443}

func nftAddTableArgs() []string {
	return []string{"add", "table", "ip", redirectTable}
}

func nftDeleteTableArgs() []string {
	return []string{"delete", "table", "ip", redirectTable}
}

func nftAddSetArgs() []string {
	return []string{
		"add", "set", "ip", redirectTable, redirectSet,
		"{ type ipv4_addr ; }",
	}
}

func nftAddChainArgs() []string {
	return []string{
		"add", "chain", "ip", redirectTable, redirectChain,
		"{ type nat hook output priority -100 ; policy accept ; }",
	}
}

// nftAddRuleArgs builds the rule that redirects blocked-set destinations on the
// monitored ports to the local transparent proxy port.
func nftAddRuleArgs(toPort int) []string {
	ports := make([]string, len(redirectPorts))
	for i, p := range redirectPorts {
		ports[i] = strconv.Itoa(p)
	}
	return []string{
		"add", "rule", "ip", redirectTable, redirectChain,
		"ip", "daddr", "@" + redirectSet,
		"tcp", "dport", "{ " + strings.Join(ports, ", ") + " }",
		"redirect", "to", ":" + strconv.Itoa(toPort),
	}
}

func nftAddElementArgs(ip string) []string {
	return []string{
		"add", "element", "ip", redirectTable, redirectSet,
		"{ " + ip + " }",
	}
}

func nftDeleteElementArgs(ip string) []string {
	return []string{
		"delete", "element", "ip", redirectTable, redirectSet,
		"{ " + ip + " }",
	}
}

// quoteArgs renders an argv as a single line for logging/debugging.
func quoteArgs(args []string) string {
	return fmt.Sprintf("nft %s", strings.Join(args, " "))
}
