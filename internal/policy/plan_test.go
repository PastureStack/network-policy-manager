package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildPlanCountsAndPrivacy(t *testing.T) {
	t.Parallel()
	plan, err := BuildPlan(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != PlanSchema || plan.DefaultAction != "deny" {
		t.Fatalf("unexpected plan header: %#v", plan)
	}
	if plan.Inventory != (Inventory{StackCount: 2, ServiceCount: 3, WorkloadCount: 6, LocalWorkloadCount: 5, SystemWorkloadCount: 1, NonSystemWorkloadCount: 5}) {
		t.Fatalf("unexpected inventory: %#v", plan.Inventory)
	}
	wantRules := RuleCounts{Total: 6, Allow: 5, Deny: 1, WithinStack: 1, WithinService: 1, WithinLinked: 1, BetweenSelector: 1, BetweenGroupBy: 1, FromTo: 1}
	if plan.Rules != wantRules {
		t.Fatalf("unexpected rule counts: %#v", plan.Rules)
	}
	wantCompilation := Compilation{EstimatedRelationships: 49, EstimatedPortScopes: 4, LabelGroups: 2}
	if plan.Compilation != wantCompilation {
		t.Fatalf("unexpected compilation: %#v", plan.Compilation)
	}
	if plan.Safeguards.Mode != "audit-only" || plan.Safeguards.AppliesHostChanges || plan.Safeguards.ReadsMetadata || plan.Safeguards.AcceptsNetworkAddresses || plan.Safeguards.AcceptsSecretMaterial || plan.Safeguards.EmitsIdentifiers || plan.Safeguards.ProductionReady {
		t.Fatalf("unexpected safeguards: %#v", plan.Safeguards)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"host-a", "frontend-a", "tier", "worker", "zone"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("plan leaked %q", secret)
		}
	}
}

func TestBuildPlanDeterministicNormalization(t *testing.T) {
	t.Parallel()
	first := validConfig()
	second := validConfig()
	reverseStacks(second.Stacks)
	reverseServices(second.Services)
	reverseWorkloads(second.Workloads)
	second.Services[2].Labels = map[string]string{"TIER": "WEB"}
	second.Workloads[5].Labels = map[string]string{"ZONE": "EAST"}
	left, err := BuildPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildPlan(second)
	if err != nil {
		t.Fatal(err)
	}
	if left.NormalizedSHA256 != right.NormalizedSHA256 {
		t.Fatalf("digests differ: %s != %s", left.NormalizedSHA256, right.NormalizedSHA256)
	}
}

func TestZeroMatchAndUnscopedPortEstimate(t *testing.T) {
	t.Parallel()
	config := validConfig()
	config.Policy.Rules = []Rule{{From: &Endpoint{Selector: "tier=missing"}, To: &Endpoint{Selector: "tier=api"}, Action: "deny"}}
	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Compilation.RulesWithZeroMatches != 1 || plan.Compilation.EstimatedRelationships != 0 || plan.Compilation.EstimatedPortScopes != 0 {
		t.Fatalf("unexpected compilation: %#v", plan.Compilation)
	}
}

func reverseStacks(values []Stack) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
func reverseServices(values []Service) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
func reverseWorkloads(values []Workload) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
