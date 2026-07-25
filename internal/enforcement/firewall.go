package enforcement

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type FirewallBackend interface {
	Apply(context.Context, FirewallPlan) error
	Cleanup(context.Context) error
}

type NFTBackend struct {
	Binary string
}

func (backend NFTBackend) Apply(ctx context.Context, plan FirewallPlan) error {
	script, err := RenderNFT(plan)
	if err != nil {
		return err
	}
	binary := backend.Binary
	if binary == "" {
		binary = "nft"
	}
	exists := tableExists(ctx, binary)
	if exists {
		script = "delete table " + firewallFamily + " " + firewallTable + "\n" + script
	}
	if err := runNFT(ctx, binary, true, script); err != nil {
		return errors.New("firewall transaction validation failed")
	}
	if err := runNFT(ctx, binary, false, script); err != nil {
		return errors.New("firewall transaction failed")
	}
	return nil
}

func (backend NFTBackend) Cleanup(ctx context.Context) error {
	binary := backend.Binary
	if binary == "" {
		binary = "nft"
	}
	if !tableExists(ctx, binary) {
		return nil
	}
	script := "delete table " + firewallFamily + " " + firewallTable + "\n"
	if err := runNFT(ctx, binary, true, script); err != nil {
		return errors.New("firewall cleanup validation failed")
	}
	if err := runNFT(ctx, binary, false, script); err != nil {
		return errors.New("firewall cleanup failed")
	}
	return nil
}

func tableExists(ctx context.Context, binary string) bool {
	command := exec.CommandContext(ctx, binary, "list", "table", firewallFamily, firewallTable)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run() == nil
}

func runNFT(ctx context.Context, binary string, check bool, script string) error {
	arguments := []string{"-f", "-"}
	if check {
		arguments = []string{"-c", "-f", "-"}
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdin = strings.NewReader(script)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func RenderNFT(plan FirewallPlan) (string, error) {
	if !plan.Subnet.IsValid() || !plan.Subnet.Addr().Is4() {
		return "", errors.New("firewall plan subnet is invalid")
	}
	if plan.DefaultAction != "allow" && plan.DefaultAction != "deny" {
		return "", errors.New("firewall plan default action is invalid")
	}

	type setDefinition struct {
		name      string
		addresses []netip.Addr
	}
	setByKey := make(map[string]string)
	var sets []setDefinition
	getSet := func(addresses []netip.Addr) (string, error) {
		if len(addresses) == 0 {
			return "", nil
		}
		addresses = uniqueAddresses(addresses)
		var keyBuilder strings.Builder
		for _, address := range addresses {
			if !address.IsValid() || !address.Is4() || !plan.Subnet.Contains(address) {
				return "", errors.New("firewall plan contains an invalid address")
			}
			keyBuilder.WriteString(address.String())
			keyBuilder.WriteByte(',')
		}
		key := keyBuilder.String()
		if name, exists := setByKey[key]; exists {
			return name, nil
		}
		name := fmt.Sprintf("s%03d", len(sets))
		setByKey[key] = name
		sets = append(sets, setDefinition{name: name, addresses: addresses})
		return name, nil
	}

	type renderedRule struct {
		source      string
		destination string
		port        *PortMatch
		action      string
	}
	rules := make([]renderedRule, 0, len(plan.Rules))
	for _, rule := range plan.Rules {
		if rule.Action != "allow" && rule.Action != "deny" {
			return "", errors.New("firewall plan contains an invalid action")
		}
		source, err := getSet(rule.Sources)
		if err != nil {
			return "", err
		}
		destination, err := getSet(rule.Destinations)
		if err != nil {
			return "", err
		}
		if source == "" && destination == "" {
			return "", errors.New("firewall plan contains an unconstrained rule")
		}
		if rule.Port != nil {
			if rule.Port.Number == 0 || (rule.Port.Protocol != "tcp" && rule.Port.Protocol != "udp") {
				return "", errors.New("firewall plan contains an invalid port")
			}
		}
		rules = append(rules, renderedRule{
			source:      source,
			destination: destination,
			port:        rule.Port,
			action:      rule.Action,
		})
	}

	var output bytes.Buffer
	output.WriteString("table ")
	output.WriteString(firewallFamily)
	output.WriteByte(' ')
	output.WriteString(firewallTable)
	output.WriteString(" {\n")
	for _, set := range sets {
		output.WriteString("  set ")
		output.WriteString(set.name)
		output.WriteString(" {\n    type ipv4_addr\n    elements = { ")
		for index, address := range set.addresses {
			if index > 0 {
				output.WriteString(", ")
			}
			output.WriteString(address.String())
		}
		output.WriteString(" }\n  }\n")
	}
	output.WriteString("  chain forward {\n")
	output.WriteString("    type filter hook forward priority -10; policy accept;\n")
	output.WriteString("    ip saddr ")
	output.WriteString(plan.Subnet.String())
	output.WriteString(" ip daddr ")
	output.WriteString(plan.Subnet.String())
	output.WriteString(" jump enforce\n")
	output.WriteString("  }\n")
	output.WriteString("  chain enforce {\n")
	output.WriteString("    ct state established,related return\n")
	for _, rule := range rules {
		output.WriteString("    ")
		if rule.source != "" {
			output.WriteString("ip saddr @")
			output.WriteString(rule.source)
			output.WriteByte(' ')
		}
		if rule.destination != "" {
			output.WriteString("ip daddr @")
			output.WriteString(rule.destination)
			output.WriteByte(' ')
		}
		if rule.port != nil {
			output.WriteString(rule.port.Protocol)
			output.WriteString(" dport ")
			output.WriteString(strconv.Itoa(int(rule.port.Number)))
			output.WriteByte(' ')
		}
		output.WriteString("counter ")
		if rule.action == "allow" {
			output.WriteString("return\n")
		} else {
			output.WriteString("drop\n")
		}
	}
	output.WriteString("    return\n")
	output.WriteString("  }\n")
	output.WriteString("}\n")
	return output.String(), nil
}

func sortedAddresses(addresses []netip.Addr) []netip.Addr {
	copy := append([]netip.Addr(nil), addresses...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].Less(copy[j]) })
	return copy
}
