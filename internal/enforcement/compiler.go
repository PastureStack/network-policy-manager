package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/PastureStack/network-policy-manager/internal/policy"
)

func Compile(snapshot Snapshot) (FirewallPlan, error) {
	if !snapshot.Subnet.IsValid() || !snapshot.Subnet.Addr().Is4() {
		return FirewallPlan{}, errors.New("snapshot subnet is invalid")
	}
	if snapshot.LocalHostID == "" {
		return FirewallPlan{}, errors.New("snapshot local host is missing")
	}

	plan := FirewallPlan{
		Subnet:          snapshot.Subnet.Masked(),
		DefaultAction:   snapshot.Policy.DefaultAction,
		WorkloadCount:   len(snapshot.Workloads),
		PolicyRuleCount: len(snapshot.Policy.Rules),
	}

	allByID := make(map[string]Workload, len(snapshot.Workloads))
	var allSystem []netip.Addr
	var localApplication []netip.Addr
	for _, workload := range snapshot.Workloads {
		if workload.ID == "" || !workload.IP.IsValid() || !workload.IP.Is4() || !snapshot.Subnet.Contains(workload.IP) {
			return FirewallPlan{}, errors.New("snapshot contains an invalid workload")
		}
		if _, exists := allByID[workload.ID]; exists {
			return FirewallPlan{}, errors.New("snapshot contains a duplicate workload")
		}
		allByID[workload.ID] = workload
		if workload.System {
			allSystem = append(allSystem, workload.IP)
		} else if workload.HostID == snapshot.LocalHostID {
			localApplication = append(localApplication, workload.IP)
			plan.LocalWorkloadCount++
		}
	}

	if len(allSystem) > 0 {
		plan.Rules = append(plan.Rules, FirewallRule{
			Sources: uniqueAddresses(allSystem),
			Action:  "allow",
		})
	}

	for _, rule := range snapshot.Policy.Rules {
		before := len(plan.Rules)
		switch {
		case rule.Within != "":
			if err := compileWithin(&plan, snapshot, rule); err != nil {
				return FirewallPlan{}, err
			}
		case rule.Between != nil:
			if err := compileBetween(&plan, snapshot, rule); err != nil {
				return FirewallPlan{}, err
			}
		case rule.From != nil && rule.To != nil:
			if err := compileDirected(&plan, snapshot, rule); err != nil {
				return FirewallPlan{}, err
			}
		default:
			return FirewallPlan{}, errors.New("snapshot contains an unsupported policy rule")
		}
		if len(plan.Rules) == before {
			plan.ZeroMatchCount++
		}
	}

	if len(localApplication) > 0 {
		plan.Rules = append(plan.Rules, FirewallRule{
			Destinations: uniqueAddresses(localApplication),
			Action:       snapshot.Policy.DefaultAction,
		})
	}
	digest, err := digestPlan(plan)
	if err != nil {
		return FirewallPlan{}, err
	}
	plan.Digest = digest
	return plan, nil
}
func compileWithin(plan *FirewallPlan, snapshot Snapshot, rule policy.Rule) error {
	type group struct {
		all   []netip.Addr
		local []netip.Addr
	}
	groups := make(map[string]*group)
	switch rule.Within {
	case "stack":
		for _, workload := range snapshot.Workloads {
			if workload.System {
				continue
			}
			item := ensureGroup(groups, workload.StackID)
			item.all = append(item.all, workload.IP)
			if workload.HostID == snapshot.LocalHostID {
				item.local = append(item.local, workload.IP)
			}
		}
	case "service":
		for _, workload := range snapshot.Workloads {
			if workload.System || workload.PrimaryServiceID == "" {
				continue
			}
			item := ensureGroup(groups, workload.PrimaryServiceID)
			item.all = append(item.all, workload.IP)
			if workload.HostID == snapshot.LocalHostID {
				item.local = append(item.local, workload.IP)
			}
		}
	case "linked":
		return compileLinked(plan, snapshot, rule)
	default:
		return errors.New("snapshot contains an unsupported within rule")
	}

	for _, key := range sortedGroupKeys(groups) {
		item := groups[key]
		appendAddressRule(plan, item.all, item.local, rule.Ports, rule.Action)
	}
	return nil
}

func compileLinked(plan *FirewallPlan, snapshot Snapshot, rule policy.Rule) error {
	workloadsByService := make(map[string][]Workload)
	for _, workload := range snapshot.Workloads {
		if workload.System || workload.PrimaryServiceID == "" {
			continue
		}
		workloadsByService[workload.PrimaryServiceID] = append(workloadsByService[workload.PrimaryServiceID], workload)
	}

	targetSources := make(map[string]map[string]struct{})
	for source, targets := range snapshot.ServiceLinks {
		for _, target := range targets {
			if targetSources[target] == nil {
				targetSources[target] = make(map[string]struct{})
			}
			targetSources[target][source] = struct{}{}
		}
	}
	for _, target := range sortedStringSetKeys(targetSources) {
		var sources []netip.Addr
		var destinations []netip.Addr
		for source := range targetSources[target] {
			for _, workload := range workloadsByService[source] {
				sources = append(sources, workload.IP)
			}
		}
		for _, workload := range workloadsByService[target] {
			if workload.HostID == snapshot.LocalHostID {
				destinations = append(destinations, workload.IP)
			}
		}
		appendAddressRule(plan, sources, destinations, rule.Ports, rule.Action)
	}

	workloadByID := make(map[string]Workload, len(snapshot.Workloads))
	for _, workload := range snapshot.Workloads {
		workloadByID[workload.ID] = workload
	}
	containerTargets := make(map[string]map[string]struct{})
	for source, targets := range snapshot.ContainerLinks {
		for _, target := range targets {
			if containerTargets[target] == nil {
				containerTargets[target] = make(map[string]struct{})
			}
			containerTargets[target][source] = struct{}{}
		}
	}
	for _, target := range sortedStringSetKeys(containerTargets) {
		destination, ok := workloadByID[target]
		if !ok || destination.System || destination.HostID != snapshot.LocalHostID {
			continue
		}
		var sources []netip.Addr
		for source := range containerTargets[target] {
			workload, exists := workloadByID[source]
			if exists && !workload.System {
				sources = append(sources, workload.IP)
			}
		}
		appendAddressRule(plan, sources, []netip.Addr{destination.IP}, rule.Ports, rule.Action)
	}
	return nil
}

func compileBetween(plan *FirewallPlan, snapshot Snapshot, rule policy.Rule) error {
	if rule.Between.Selector != "" {
		var all []netip.Addr
		var local []netip.Addr
		for _, workload := range snapshot.Workloads {
			if workload.System {
				continue
			}
			matches, err := policy.MatchSelector(rule.Between.Selector, workload.Labels)
			if err != nil {
				return errors.New("selector evaluation failed")
			}
			if !matches {
				continue
			}
			all = append(all, workload.IP)
			if workload.HostID == snapshot.LocalHostID {
				local = append(local, workload.IP)
			}
		}
		appendAddressRule(plan, all, local, rule.Ports, rule.Action)
		return nil
	}

	type group struct {
		all   []netip.Addr
		local []netip.Addr
	}
	groups := make(map[string]*group)
	for _, workload := range snapshot.Workloads {
		if workload.System {
			continue
		}
		value, exists := workload.Labels[rule.Between.GroupBy]
		if !exists {
			continue
		}
		item := ensureGroup(groups, value)
		item.all = append(item.all, workload.IP)
		if workload.HostID == snapshot.LocalHostID {
			item.local = append(item.local, workload.IP)
		}
	}
	for _, key := range sortedGroupKeys(groups) {
		item := groups[key]
		appendAddressRule(plan, item.all, item.local, rule.Ports, rule.Action)
	}
	return nil
}

func compileDirected(plan *FirewallPlan, snapshot Snapshot, rule policy.Rule) error {
	var sources []netip.Addr
	var destinations []netip.Addr
	for _, workload := range snapshot.Workloads {
		if workload.System {
			continue
		}
		fromMatch, err := policy.MatchSelector(rule.From.Selector, workload.Labels)
		if err != nil {
			return errors.New("source selector evaluation failed")
		}
		if fromMatch {
			sources = append(sources, workload.IP)
		}
		if workload.HostID == snapshot.LocalHostID {
			toMatch, matchErr := policy.MatchSelector(rule.To.Selector, workload.Labels)
			if matchErr != nil {
				return errors.New("destination selector evaluation failed")
			}
			if toMatch {
				destinations = append(destinations, workload.IP)
			}
		}
	}
	appendAddressRule(plan, sources, destinations, rule.Ports, rule.Action)
	return nil
}

func appendAddressRule(plan *FirewallPlan, sources, destinations []netip.Addr, ports []string, action string) {
	sources = uniqueAddresses(sources)
	destinations = uniqueAddresses(destinations)
	if len(sources) == 0 || len(destinations) == 0 {
		return
	}
	if len(ports) == 0 {
		plan.Rules = append(plan.Rules, FirewallRule{
			Sources:      sources,
			Destinations: destinations,
			Action:       action,
		})
		return
	}
	for _, encoded := range ports {
		parts := strings.Split(encoded, "/")
		number, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			continue
		}
		protocols := []string{"tcp", "udp"}
		if len(parts) == 2 {
			protocols = []string{parts[1]}
		}
		for _, protocol := range protocols {
			plan.Rules = append(plan.Rules, FirewallRule{
				Sources:      sources,
				Destinations: destinations,
				Port:         &PortMatch{Number: uint16(number), Protocol: protocol},
				Action:       action,
			})
		}
	}
}

func uniqueAddresses(addresses []netip.Addr) []netip.Addr {
	if len(addresses) == 0 {
		return nil
	}
	copy := append([]netip.Addr(nil), addresses...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].Less(copy[j]) })
	output := copy[:0]
	for _, address := range copy {
		if len(output) == 0 || output[len(output)-1] != address {
			output = append(output, address)
		}
	}
	return output
}

func ensureGroup[T any](groups map[string]*T, key string) *T {
	item := groups[key]
	if item == nil {
		item = new(T)
		groups[key] = item
	}
	return item
}

func sortedGroupKeys[T any](groups map[string]*T) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringSetKeys(groups map[string]map[string]struct{}) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func digestPlan(plan FirewallPlan) (string, error) {
	copy := plan
	copy.Digest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", fmt.Errorf("encode firewall plan: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func FailOpenPlan(previous FirewallPlan) (FirewallPlan, error) {
	plan := FirewallPlan{
		Subnet:             previous.Subnet,
		DefaultAction:      "allow",
		WorkloadCount:      previous.WorkloadCount,
		LocalWorkloadCount: previous.LocalWorkloadCount,
		PolicyRuleCount:    previous.PolicyRuleCount,
		ZeroMatchCount:     previous.ZeroMatchCount,
		FailOpen:           true,
	}
	digest, err := digestPlan(plan)
	if err != nil {
		return FirewallPlan{}, err
	}
	plan.Digest = digest
	return plan, nil
}
