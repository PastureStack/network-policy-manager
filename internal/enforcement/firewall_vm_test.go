package enforcement

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Opt-in isolated-VM gate: policy owns only its table, regardless of which
// firewall frontend Docker and Network Plugin Manager use on the host.
func TestOwnedPolicyTableCoexistsWithDockerFirewallOnVM(t *testing.T) {
	mode := os.Getenv("PASTURESTACK_POLICY_VM_MODE")
	if mode == "" {
		t.Skip("set PASTURESTACK_POLICY_VM_MODE on an isolated root VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("firewall integration test requires root")
	}
	containers, err := exec.Command("docker", "ps", "-aq").CombinedOutput()
	if err != nil || len(bytes.TrimSpace(containers)) != 0 {
		t.Fatalf("refusing nonempty or uninspectable Docker host: %v: %s", err, containers)
	}
	if tableExists(context.Background(), "nft") {
		t.Fatal("refusing to replace a pre-existing policy table")
	}
	driver, err := exec.Command("docker", "info", "--format", "{{.FirewallBackend.Driver}}").CombinedOutput()
	if err != nil {
		t.Fatalf("inspect Docker firewall driver: %v: %s", err, driver)
	}
	var snapshot []string
	switch mode {
	case "nftables":
		if strings.TrimSpace(string(driver)) != "nftables" {
			t.Fatalf("expected native Docker firewall, got %q", driver)
		}
		snapshot = []string{"nft", "list", "table", "ip", "docker-bridges"}
	case "iptables-nft", "iptables-legacy":
		if strings.TrimSpace(string(driver)) != "iptables" {
			t.Fatalf("expected Docker iptables firewall, got %q", driver)
		}
		command := mode
		if out, err := exec.Command(command, "-t", "nat", "-S", "DOCKER").CombinedOutput(); err != nil {
			t.Fatalf("Docker does not own %s NAT: %v: %s", mode, err, out)
		}
		snapshot = []string{command + "-save"}
	default:
		t.Fatalf("unsupported VM test mode %q", mode)
	}
	readDocker := func() []byte {
		out, err := exec.Command(snapshot[0], snapshot[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("read Docker firewall snapshot: %v: %s", err, out)
		}
		return out
	}
	before := readDocker()
	backend := NFTBackend{}
	t.Cleanup(func() {
		if err := backend.Cleanup(context.Background()); err != nil {
			t.Errorf("cleanup test-owned policy table: %v", err)
		}
	})
	plan := FirewallPlan{Subnet: netip.MustParsePrefix("198.18.250.0/24"), DefaultAction: "allow"}
	for iteration := 0; iteration < 2; iteration++ {
		if err := backend.Apply(context.Background(), plan); err != nil {
			t.Fatalf("apply policy iteration %d: %v", iteration, err)
		}
		if !tableExists(context.Background(), "nft") {
			t.Fatalf("policy table absent after apply %d", iteration)
		}
		if after := readDocker(); !bytes.Equal(before, after) {
			t.Fatalf("Docker-owned rules changed after policy apply %d: %s", iteration, fmt.Sprint(snapshot))
		}
	}
	if err := backend.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup policy table: %v", err)
	}
	if tableExists(context.Background(), "nft") {
		t.Fatal("test-owned policy table remains after cleanup")
	}
	if after := readDocker(); !bytes.Equal(before, after) {
		t.Fatalf("Docker-owned rules changed after policy cleanup: %s", fmt.Sprint(snapshot))
	}
}
