package enforcement

import (
	"net/netip"
	"time"

	"github.com/PastureStack/network-policy-manager/internal/policy"
)

const (
	defaultMetadataURL = "http://169.254.169.250/2016-07-29"
	maxMetadataBytes   = 16 << 20
	firewallFamily     = "inet"
	firewallTable      = "pasturestack_policy"
)

// Snapshot contains only the bounded topology needed by the compiler. Raw
// platform identifiers stay in memory and are never included in status output.
type Snapshot struct {
	Subnet         netip.Prefix
	LocalHostID    string
	Workloads      []Workload
	ServiceLinks   map[string][]string
	ContainerLinks map[string][]string
	Policy         policy.Policy
}

type Workload struct {
	ID               string
	IP               netip.Addr
	HostID           string
	StackID          string
	ServiceID        string
	PrimaryServiceID string
	System           bool
	Labels           map[string]string
}

type PortMatch struct {
	Number   uint16
	Protocol string
}

type FirewallRule struct {
	Sources      []netip.Addr
	Destinations []netip.Addr
	Port         *PortMatch
	Action       string
}

type FirewallPlan struct {
	Subnet             netip.Prefix
	Digest             string
	DefaultAction      string
	Rules              []FirewallRule
	WorkloadCount      int
	LocalWorkloadCount int
	PolicyRuleCount    int
	ZeroMatchCount     int
	FailOpen           bool
}

type PublicStatus struct {
	Status             string    `json:"status"`
	Version            string    `json:"version"`
	PolicySHA256       string    `json:"policy_sha256,omitempty"`
	DefaultAction      string    `json:"default_action,omitempty"`
	LastSuccess        time.Time `json:"last_success,omitempty"`
	LastAttempt        time.Time `json:"last_attempt,omitempty"`
	WorkloadCount      int       `json:"workload_count"`
	LocalWorkloadCount int       `json:"local_workload_count"`
	PolicyRuleCount    int       `json:"policy_rule_count"`
	FirewallRuleCount  int       `json:"firewall_rule_count"`
	ZeroMatchCount     int       `json:"zero_match_count"`
	FailureCount       uint64    `json:"failure_count"`
	FailOpen           bool      `json:"fail_open"`
}
