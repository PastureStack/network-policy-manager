package enforcement

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetadataSnapshot(t *testing.T) {
	responses := map[string]string{
		"/self/host": `{"uuid":"host-local"}`,
		"/networks": `[{
			"uuid":"network-a",
			"is_default":true,
			"default_policy_action":"deny",
			"metadata":{"cniConfig":{"10-pasture.conf":{"bridgeSubnet":"10.42.0.0/16"}}},
			"policy":[{"within":"stack","action":"allow"},{"from":{"selector":"tier=web"},"to":{"selector":"tier=api"},"ports":["443/tcp"],"action":"allow"}]
		}]`,
		"/stacks": `[{
			"uuid":"stack-a",
			"name":"application",
			"system":false,
			"services":[{
				"uuid":"service-web",
				"name":"web",
				"stack_uuid":"stack-a",
				"stack_name":"application",
				"primary_service_name":"web",
				"labels":{"tier":"web"},
				"links":{"application/api":"api"},
				"containers":[{
					"uuid":"workload-web",
					"host_uuid":"host-local",
					"stack_uuid":"stack-a",
					"service_uuid":"service-web",
					"network_uuid":"network-a",
					"primary_ip":"10.42.1.10",
					"state":"running",
					"labels":{"role":"frontend"}
				}]
			},{
				"uuid":"service-api",
				"name":"api",
				"stack_uuid":"stack-a",
				"stack_name":"application",
				"primary_service_name":"api",
				"labels":{"tier":"api"},
				"containers":[{
					"uuid":"workload-api",
					"host_uuid":"host-remote",
					"stack_uuid":"stack-a",
					"service_uuid":"service-api",
					"network_uuid":"network-a",
					"primary_ip":"10.42.2.20",
					"state":"running"
				}]
			}]
		}]`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		value, exists := responses[request.URL.Path]
		if !exists {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(value))
	}))
	defer server.Close()

	client := NewMetadataClient(server.URL)
	snapshot, err := client.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot returned an error: %v", err)
	}
	if got := snapshot.Subnet.String(); got != "10.42.0.0/16" {
		t.Fatalf("unexpected subnet %q", got)
	}
	if len(snapshot.Workloads) != 2 || len(snapshot.Policy.Rules) != 2 {
		t.Fatalf("unexpected snapshot counts: workloads=%d rules=%d", len(snapshot.Workloads), len(snapshot.Policy.Rules))
	}
	if snapshot.Workloads[0].Labels["tier"] != "web" || snapshot.Workloads[0].Labels["role"] != "frontend" {
		t.Fatalf("labels were not combined")
	}
	if got := snapshot.ServiceLinks["service-web"]; len(got) != 1 || got[0] != "service-api" {
		t.Fatalf("service link was not resolved: %#v", got)
	}
}

func TestParsePolicyAcceptsStringEncodedRules(t *testing.T) {
	parsed, err := parsePolicy("deny", []byte(`["{\"within\":\"service\",\"action\":\"allow\"}"]`))
	if err != nil {
		t.Fatalf("parsePolicy returned an error: %v", err)
	}
	if len(parsed.Rules) != 1 || parsed.Rules[0].Within != "service" {
		t.Fatalf("unexpected parsed policy: %#v", parsed)
	}
}
