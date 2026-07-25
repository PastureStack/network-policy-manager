package policy

func validConfig() Config {
	return Config{
		Schema:      InputSchema,
		LocalHostID: "host-a",
		Stacks: []Stack{
			{ID: "application"},
			{ID: "platform", System: true},
		},
		Services: []Service{
			{ID: "frontend", StackID: "application", Labels: map[string]string{"tier": "web"}, Links: []string{"backend"}},
			{ID: "backend", StackID: "application", Labels: map[string]string{"tier": "api"}},
			{ID: "sidecar", StackID: "application", Labels: map[string]string{"tier": "web"}, PrimaryServiceID: "frontend"},
		},
		Workloads: []Workload{
			{ID: "frontend-a", HostID: "host-a", StackID: "application", ServiceID: "frontend", Labels: map[string]string{"zone": "east"}},
			{ID: "sidecar-a", HostID: "host-a", StackID: "application", ServiceID: "sidecar", Labels: map[string]string{"zone": "east"}},
			{ID: "backend-a", HostID: "host-a", StackID: "application", ServiceID: "backend", Labels: map[string]string{"zone": "west"}},
			{ID: "standalone-a", HostID: "host-a", StackID: "application", Labels: map[string]string{"tier": "worker"}, Links: []string{"standalone-b"}},
			{ID: "standalone-b", HostID: "host-b", StackID: "application", Labels: map[string]string{"tier": "worker"}},
			{ID: "system-a", HostID: "host-a", StackID: "platform", Labels: map[string]string{"tier": "system"}},
		},
		Policy: Policy{DefaultAction: "deny", Rules: []Rule{
			{Within: "stack", Action: "allow"},
			{Within: "service", Action: "allow"},
			{Within: "linked", Action: "allow"},
			{Between: &Between{Selector: "tier in (web,worker)"}, Action: "allow"},
			{Between: &Between{GroupBy: "zone"}, Action: "deny"},
			{From: &Endpoint{Selector: "tier=web"}, To: &Endpoint{Selector: "tier=api"}, Ports: []string{"443/tcp", "53/udp"}, Action: "allow"},
		}},
	}
}
