package policy

import (
	"strings"
	"testing"
)

func TestValidationRejectsInvalidTopology(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"schema", func(c *Config) { c.Schema = "wrong" }},
		{"local host", func(c *Config) { c.LocalHostID = "INVALID" }},
		{"empty stacks", func(c *Config) { c.Stacks = nil }},
		{"too many stacks", func(c *Config) {
			c.Stacks = make([]Stack, MaxStacks+1)
			for i := range c.Stacks {
				c.Stacks[i].ID = "stack-" + alphaID(i)
			}
		}},
		{"too many services", func(c *Config) { c.Services = make([]Service, MaxServices+1) }},
		{"empty workloads", func(c *Config) { c.Workloads = nil }},
		{"too many workloads", func(c *Config) { c.Workloads = make([]Workload, MaxWorkloads+1) }},
		{"too many rules", func(c *Config) { c.Policy.Rules = make([]Rule, MaxRules+1) }},
		{"default action", func(c *Config) { c.Policy.DefaultAction = "observe" }},
		{"invalid stack id", func(c *Config) { c.Stacks[0].ID = "Bad" }},
		{"duplicate stack", func(c *Config) { c.Stacks[1].ID = c.Stacks[0].ID }},
		{"invalid service id", func(c *Config) { c.Services[0].ID = "Bad" }},
		{"duplicate service", func(c *Config) { c.Services[1].ID = c.Services[0].ID }},
		{"unknown service stack", func(c *Config) { c.Services[0].StackID = "missing" }},
		{"invalid service label", func(c *Config) { c.Services[0].Labels = map[string]string{"bad key": "x"} }},
		{"duplicate service label case", func(c *Config) { c.Services[0].Labels = map[string]string{"Tier": "web", "tier": "web"} }},
		{"too many service labels", func(c *Config) { c.Services[0].Labels = manyLabels(65) }},
		{"invalid service label value", func(c *Config) { c.Services[0].Labels = map[string]string{"tier": "bad\nvalue"} }},
		{"invalid primary", func(c *Config) { c.Services[2].PrimaryServiceID = "missing" }},
		{"primary self", func(c *Config) { c.Services[2].PrimaryServiceID = "sidecar" }},
		{"primary chain", func(c *Config) {
			c.Services[1].PrimaryServiceID = "frontend"
			c.Services[2].PrimaryServiceID = "backend"
		}},
		{"service self link", func(c *Config) { c.Services[0].Links = []string{"frontend"} }},
		{"service unknown link", func(c *Config) { c.Services[0].Links = []string{"missing"} }},
		{"service duplicate link", func(c *Config) { c.Services[0].Links = []string{"backend", "backend"} }},
		{"invalid workload id", func(c *Config) { c.Workloads[0].ID = "Bad" }},
		{"invalid workload host", func(c *Config) { c.Workloads[0].HostID = "Bad" }},
		{"duplicate workload", func(c *Config) { c.Workloads[1].ID = c.Workloads[0].ID }},
		{"unknown workload stack", func(c *Config) { c.Workloads[0].StackID = "missing" }},
		{"invalid workload service", func(c *Config) { c.Workloads[0].ServiceID = "missing" }},
		{"conflicting inherited label", func(c *Config) { c.Workloads[0].Labels["tier"] = "other" }},
		{"workload self link", func(c *Config) { c.Workloads[3].Links = []string{"standalone-a"} }},
		{"workload unknown link", func(c *Config) { c.Workloads[3].Links = []string{"missing"} }},
		{"workload duplicate link", func(c *Config) { c.Workloads[3].Links = []string{"standalone-b", "standalone-b"} }},
		{"local host absent", func(c *Config) { c.LocalHostID = "host-c" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.edit(&config)
			if _, err := BuildPlan(config); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestValidationRejectsInvalidRules(t *testing.T) {
	t.Parallel()
	tests := []Rule{
		{Within: "stack", Action: "observe"},
		{Action: "allow"},
		{Within: "stack", Between: &Between{GroupBy: "tier"}, Action: "allow"},
		{Within: "host", Action: "allow"},
		{Within: "stack", Ports: []string{"80"}, Action: "allow"},
		{Between: &Between{}, Action: "allow"},
		{Between: &Between{Selector: "tier=web", GroupBy: "tier"}, Action: "allow"},
		{Between: &Between{Selector: "bad > value"}, Action: "allow"},
		{Between: &Between{GroupBy: "bad key"}, Action: "allow"},
		{Between: &Between{GroupBy: "tier"}, From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, Action: "allow"},
		{To: &Endpoint{Selector: "tier=api"}, Action: "allow"},
		{From: &Endpoint{Selector: "bad > value"}, To: &Endpoint{Selector: "tier=api"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "bad > value"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"0"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"65536"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"80/sctp"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"80/tcp/extra"}, Action: "allow"},
		{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"080", "80"}, Action: "allow"},
	}
	for index, rule := range tests {
		config := validConfig()
		config.Policy.Rules = []Rule{rule}
		if _, err := BuildPlan(config); err == nil {
			t.Fatalf("case %d: expected an error", index)
		}
	}
	config := validConfig()
	config.Policy.Rules = []Rule{{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: make([]string, 65), Action: "allow"}}
	if _, err := BuildPlan(config); err == nil {
		t.Fatal("expected port limit error")
	}
}

func TestAcceptedPortAndLabelNormalization(t *testing.T) {
	t.Parallel()
	config := validConfig()
	config.Services[0].Labels = map[string]string{"Tier": "Web"}
	config.Workloads[0].Labels = map[string]string{"TIER": "WEB", "Zone": "East"}
	config.Policy.Rules = []Rule{{From: &Endpoint{Selector: "TIER==WEB"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"80", "53/UDP"}, Action: "allow"}}
	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Compilation.EstimatedRelationships != 2 || plan.Compilation.EstimatedPortScopes != 4 {
		t.Fatalf("unexpected estimates: %#v", plan.Compilation)
	}
}

func manyLabels(count int) map[string]string {
	labels := make(map[string]string, count)
	for index := 0; index < count; index++ {
		labels["key-"+alphaID(index)] = "value"
	}
	return labels
}

func alphaID(index int) string {
	var builder strings.Builder
	for {
		builder.WriteByte(byte('a' + index%26))
		index /= 26
		if index == 0 {
			break
		}
	}
	return builder.String()
}
