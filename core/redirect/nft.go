package redirect

import (
	"fmt"
	"log"
	"sync"
)

// NFTRedirector installs and maintains the nftables `flint_redirect` table that
// diverts traffic to detector-flagged destinations into the transparent proxy.
// It tracks which destination IPs are currently in the blocked set so add/remove
// are idempotent.
//
// The struct and its bookkeeping are platform-independent; only the actual `nft`
// invocation (runNftErr) is platform-specific, so Install() degrades to a clear
// error on systems without nftables rather than failing to compile.
type NFTRedirector struct {
	toPort int

	mu      sync.Mutex
	blocked map[string]struct{}
}

// NewNFTRedirector returns a manager that will redirect blocked destinations to
// the local proxy listening on toPort.
func NewNFTRedirector(toPort int) *NFTRedirector {
	return &NFTRedirector{toPort: toPort, blocked: make(map[string]struct{})}
}

// Install creates the table, set, chain, and redirect rule. It first deletes any
// stale table from a previous run so repeated starts never stack duplicates.
func (n *NFTRedirector) Install() error {
	_ = runNftErr(nftDeleteTableArgs()) // best effort: table may not exist yet

	for _, args := range [][]string{
		nftAddTableArgs(),
		nftAddSetArgs(),
		nftAddChainArgs(),
		nftAddRuleArgs(n.toPort),
	} {
		if err := runNftErr(args); err != nil {
			_ = runNftErr(nftDeleteTableArgs()) // roll back a partial install
			return fmt.Errorf("%s: %w", quoteArgs(args), err)
		}
	}
	log.Printf("redirect: nft table %s installed (ports %v → :%d)",
		redirectTable, redirectPorts, n.toPort)
	return nil
}

// Block adds ip to the redirect set so its traffic is diverted to the proxy.
// Idempotent: a duplicate add is a no-op.
func (n *NFTRedirector) Block(ip string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.blocked[ip]; ok {
		return nil
	}
	if err := runNftErr(nftAddElementArgs(ip)); err != nil {
		return err
	}
	n.blocked[ip] = struct{}{}
	log.Printf("redirect: now diverting %s to transparent proxy", ip)
	return nil
}

// Unblock removes ip from the redirect set so its traffic flows directly again.
func (n *NFTRedirector) Unblock(ip string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.blocked[ip]; !ok {
		return nil
	}
	if err := runNftErr(nftDeleteElementArgs(ip)); err != nil {
		return err
	}
	delete(n.blocked, ip)
	return nil
}

// Count returns how many destination IPs are currently being diverted.
func (n *NFTRedirector) Count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.blocked)
}

// Cleanup removes the entire redirect table.
func (n *NFTRedirector) Cleanup() {
	if err := runNftErr(nftDeleteTableArgs()); err != nil {
		log.Printf("redirect: nft cleanup failed (table may already be gone): %v", err)
		return
	}
	n.mu.Lock()
	n.blocked = make(map[string]struct{})
	n.mu.Unlock()
	log.Printf("redirect: nft table %s removed", redirectTable)
}
