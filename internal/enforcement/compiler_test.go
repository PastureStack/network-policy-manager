package enforcement

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/PastureStack/network-policy-manager/internal/policy"
)

func TestCompileAndRenderDirectedPolicy(t *testing.T) {
	snapshot := Snapshot{
		Subnet:      netip.MustParsePrefix("10.42.0.0/16"),
		LocalHostID: "host-a",
		Workloads: []Workload{
			{ID: "system", IP: netip.MustParseAddr("10.42.0.2"), HostID: "host-b", StackID: "system-stack", ServiceID: "system-service", PrimaryServiceID: "system-service", System: true},
			{ID: "web", IP: netip.MustParseAddr("10.42.1.10"), HostID: "host-b", StackID: "app", ServiceID: "web", PrimaryServiceID: "web", Labels: map[string]string{"tier": "web"}},
			{ID: "api", IP: netip.MustParseAddr("10.42.2.20"), HostID: "host-a", StackID: "app", ServiceID: "api", PrimaryServiceID: "api", Labels: map[string]string{"tier": "api"}},
		},
		Policy: policy.Policy{
			DefaultAction: "deny",
			Rules: []policy.Rule{{
				From:   &policy.Endpoint{Selector: "tier=web"},
				To:     &policy.Endpoint{Selector: "tier=api"},
				Ports:  []string{"443/tcp"},
				Action: "allow",
			}},
		},
	}
	normalized, err := policy.NormalizePolicy(snapshot.Policy)
	if err != nil {
		t.Fatalf("NormalizePolicy returned an error: %v", err)
	}
	snapshot.Policy = normalized

	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile returned an error: %v", err)
	}
	if len(plan.Rules) != 3 {
		t.Fatalf("expected system, directed, and default rules; got %d", len(plan.Rules))
	}
	if plan.Rules[1].Port == nil || plan.Rules[1].Port.Number != 443 || plan.Rules[1].Action != "allow" {
		t.Fatalf("unexpected directed rule: %#v", plan.Rules[1])
	}
	script, err := RenderNFT(plan)
	if err != nil {
		t.Fatalf("RenderNFT returned an error: %v", err)
	}
	for _, expected := range []string{
		"table inet pasturestack_policy",
		"type filter hook forward priority -10",
		"ct state established,related return",
		"tcp dport 443 counter return",
		"counter drop",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("rendered script is missing %q:\n%s", expected, script)
		}
	}
}

func TestCompileLinkedDirection(t *testing.T) {
	snapshot := Snapshot{
		Subnet:      netip.MustParsePrefix("10.42.0.0/16"),
		LocalHostID: "host-a",
		Workloads: []Workload{
			{ID: "consumer", IP: netip.MustParseAddr("10.42.1.10"), HostID: "host-b", StackID: "app", ServiceID: "consumer", PrimaryServiceID: "consumer"},
			{ID: "producer", IP: netip.MustParseAddr("10.42.2.20"), HostID: "host-a", StackID: "app", ServiceID: "producer", PrimaryServiceID: "producer"},
		},
		ServiceLinks: map[string][]string{"consumer": {"producer"}},
		Policy: policy.Policy{
			DefaultAction: "deny",
			Rules:         []policy.Rule{{Within: "linked", Action: "allow"}},
		},
	}
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile returned an error: %v", err)
	}
	if len(plan.Rules) != 2 {
		t.Fatalf("expected linked and default rules; got %d", len(plan.Rules))
	}
	if got := plan.Rules[0].Sources[0].String(); got != "10.42.1.10" {
		t.Fatalf("unexpected source %s", got)
	}
	if got := plan.Rules[0].Destinations[0].String(); got != "10.42.2.20" {
		t.Fatalf("unexpected destination %s", got)
	}
}
