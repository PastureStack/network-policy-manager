package policy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type normalizedConfig struct {
	Schema      string     `json:"schema"`
	LocalHostID string     `json:"local_host_id"`
	Stacks      []Stack    `json:"stacks"`
	Services    []Service  `json:"services"`
	Workloads   []Workload `json:"workloads"`
	Policy      Policy     `json:"policy"`
}

func normalize(config Config) (normalizedConfig, error) {
	if config.Schema != InputSchema {
		return normalizedConfig{}, fmt.Errorf("schema must be %q", InputSchema)
	}
	if !idPattern.MatchString(config.LocalHostID) {
		return normalizedConfig{}, errors.New("local_host_id is invalid")
	}
	if len(config.Stacks) < 1 || len(config.Stacks) > MaxStacks {
		return normalizedConfig{}, fmt.Errorf("stacks must contain between 1 and %d entries", MaxStacks)
	}
	if len(config.Services) > MaxServices {
		return normalizedConfig{}, fmt.Errorf("services may contain at most %d entries", MaxServices)
	}
	if len(config.Workloads) < 1 || len(config.Workloads) > MaxWorkloads {
		return normalizedConfig{}, fmt.Errorf("workloads must contain between 1 and %d entries", MaxWorkloads)
	}
	if len(config.Policy.Rules) > MaxRules {
		return normalizedConfig{}, fmt.Errorf("policy.rules may contain at most %d entries", MaxRules)
	}
	if config.Policy.DefaultAction != "allow" && config.Policy.DefaultAction != "deny" {
		return normalizedConfig{}, errors.New("policy.default_action must be allow or deny")
	}

	stacks := make([]Stack, 0, len(config.Stacks))
	stackByID := make(map[string]Stack, len(config.Stacks))
	for index, stack := range config.Stacks {
		if !idPattern.MatchString(stack.ID) {
			return normalizedConfig{}, fmt.Errorf("stacks[%d].id is invalid", index)
		}
		if _, exists := stackByID[stack.ID]; exists {
			return normalizedConfig{}, fmt.Errorf("stacks[%d].id is duplicated", index)
		}
		stackByID[stack.ID] = stack
		stacks = append(stacks, stack)
	}
	sort.Slice(stacks, func(i, j int) bool { return stacks[i].ID < stacks[j].ID })

	services := make([]Service, 0, len(config.Services))
	serviceByID := make(map[string]Service, len(config.Services))
	for index, service := range config.Services {
		if !idPattern.MatchString(service.ID) {
			return normalizedConfig{}, fmt.Errorf("services[%d].id is invalid", index)
		}
		if _, exists := serviceByID[service.ID]; exists {
			return normalizedConfig{}, fmt.Errorf("services[%d].id is duplicated", index)
		}
		if _, exists := stackByID[service.StackID]; !exists {
			return normalizedConfig{}, fmt.Errorf("services[%d].stack_id does not reference a stack", index)
		}
		labels, err := normalizeLabels(service.Labels)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("services[%d].labels: %w", index, err)
		}
		links, err := normalizeIDList(service.Links, 128)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("services[%d].links: %w", index, err)
		}
		copy := Service{ID: service.ID, StackID: service.StackID, Labels: labels, PrimaryServiceID: service.PrimaryServiceID, Links: links}
		serviceByID[copy.ID] = copy
		services = append(services, copy)
	}
	for index, service := range services {
		if service.PrimaryServiceID != "" {
			primary, exists := serviceByID[service.PrimaryServiceID]
			if !exists || primary.ID == service.ID || primary.StackID != service.StackID || primary.PrimaryServiceID != "" {
				return normalizedConfig{}, fmt.Errorf("services[%d].primary_service_id is invalid", index)
			}
		}
		for _, link := range service.Links {
			if link == service.ID {
				return normalizedConfig{}, fmt.Errorf("services[%d].links contains a self reference", index)
			}
			if _, exists := serviceByID[link]; !exists {
				return normalizedConfig{}, fmt.Errorf("services[%d].links contains an unknown reference", index)
			}
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })

	workloads := make([]Workload, 0, len(config.Workloads))
	workloadByID := make(map[string]Workload, len(config.Workloads))
	localFound := false
	for index, workload := range config.Workloads {
		if !idPattern.MatchString(workload.ID) || !idPattern.MatchString(workload.HostID) {
			return normalizedConfig{}, fmt.Errorf("workloads[%d] contains an invalid identifier", index)
		}
		if _, exists := workloadByID[workload.ID]; exists {
			return normalizedConfig{}, fmt.Errorf("workloads[%d].id is duplicated", index)
		}
		if _, exists := stackByID[workload.StackID]; !exists {
			return normalizedConfig{}, fmt.Errorf("workloads[%d].stack_id does not reference a stack", index)
		}
		if workload.ServiceID != "" {
			service, exists := serviceByID[workload.ServiceID]
			if !exists || service.StackID != workload.StackID {
				return normalizedConfig{}, fmt.Errorf("workloads[%d].service_id is invalid", index)
			}
		}
		labels, err := normalizeLabels(workload.Labels)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("workloads[%d].labels: %w", index, err)
		}
		if workload.ServiceID != "" {
			for key, value := range serviceByID[workload.ServiceID].Labels {
				if own, exists := labels[key]; exists && own != value {
					return normalizedConfig{}, fmt.Errorf("workloads[%d].labels conflicts with its service labels", index)
				}
			}
		}
		links, err := normalizeIDList(workload.Links, 128)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("workloads[%d].links: %w", index, err)
		}
		copy := Workload{ID: workload.ID, HostID: workload.HostID, StackID: workload.StackID, ServiceID: workload.ServiceID, Labels: labels, Links: links}
		workloadByID[copy.ID] = copy
		workloads = append(workloads, copy)
		if workload.HostID == config.LocalHostID {
			localFound = true
		}
	}
	if !localFound {
		return normalizedConfig{}, errors.New("local_host_id does not match a workload")
	}
	for index, workload := range workloads {
		for _, link := range workload.Links {
			if link == workload.ID {
				return normalizedConfig{}, fmt.Errorf("workloads[%d].links contains a self reference", index)
			}
			if _, exists := workloadByID[link]; !exists {
				return normalizedConfig{}, fmt.Errorf("workloads[%d].links contains an unknown reference", index)
			}
		}
	}
	sort.Slice(workloads, func(i, j int) bool { return workloads[i].ID < workloads[j].ID })

	rules := make([]Rule, 0, len(config.Policy.Rules))
	for index, rule := range config.Policy.Rules {
		normalized, err := normalizeRule(rule)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("policy.rules[%d]: %w", index, err)
		}
		rules = append(rules, normalized)
	}
	return normalizedConfig{
		Schema: config.Schema, LocalHostID: config.LocalHostID, Stacks: stacks, Services: services, Workloads: workloads,
		Policy: Policy{DefaultAction: config.Policy.DefaultAction, Rules: rules},
	}, nil
}

func normalizeLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) > 64 {
		return nil, errors.New("may contain at most 64 entries")
	}
	normalized := make(map[string]string, len(labels))
	for key, value := range labels {
		lowerKey := strings.ToLower(key)
		if !labelKeyPattern.MatchString(key) {
			return nil, errors.New("contains an invalid key")
		}
		if _, exists := normalized[lowerKey]; exists {
			return nil, errors.New("contains case-insensitive duplicate keys")
		}
		if len(value) > 256 || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, errors.New("contains an invalid value")
		}
		normalized[lowerKey] = strings.ToLower(value)
	}
	return normalized, nil
}

func normalizeIDList(values []string, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, fmt.Errorf("may contain at most %d entries", maximum)
	}
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	for index, value := range copy {
		if !idPattern.MatchString(value) {
			return nil, errors.New("contains an invalid identifier")
		}
		if index > 0 && value == copy[index-1] {
			return nil, errors.New("contains a duplicate identifier")
		}
	}
	return copy, nil
}

func normalizeRule(rule Rule) (Rule, error) {
	if rule.Action != "allow" && rule.Action != "deny" {
		return Rule{}, errors.New("action must be allow or deny")
	}
	forms := 0
	if rule.Within != "" {
		forms++
	}
	if rule.Between != nil {
		forms++
	}
	if rule.From != nil || rule.To != nil {
		forms++
	}
	if forms != 1 {
		return Rule{}, errors.New("exactly one of within, between, or from/to is required")
	}
	normalized := Rule{Action: rule.Action}
	if rule.Within != "" {
		if rule.Within != "stack" && rule.Within != "service" && rule.Within != "linked" {
			return Rule{}, errors.New("within must be stack, service, or linked")
		}
		if len(rule.Ports) != 0 {
			return Rule{}, errors.New("ports is only valid with from/to")
		}
		normalized.Within = rule.Within
		return normalized, nil
	}
	if rule.Between != nil {
		if rule.From != nil || rule.To != nil || len(rule.Ports) != 0 {
			return Rule{}, errors.New("between cannot be combined with from/to or ports")
		}
		hasSelector := rule.Between.Selector != ""
		hasGroup := rule.Between.GroupBy != ""
		if hasSelector == hasGroup {
			return Rule{}, errors.New("between requires exactly one of selector or group_by")
		}
		between := &Between{}
		if hasSelector {
			canonical, _, err := parseSelector(rule.Between.Selector)
			if err != nil {
				return Rule{}, err
			}
			between.Selector = canonical
		} else {
			if !labelKeyPattern.MatchString(rule.Between.GroupBy) {
				return Rule{}, errors.New("between.group_by is invalid")
			}
			between.GroupBy = strings.ToLower(rule.Between.GroupBy)
		}
		normalized.Between = between
		return normalized, nil
	}
	if rule.From == nil || rule.To == nil {
		return Rule{}, errors.New("from and to must be provided together")
	}
	from, _, err := parseSelector(rule.From.Selector)
	if err != nil {
		return Rule{}, fmt.Errorf("from: %w", err)
	}
	to, _, err := parseSelector(rule.To.Selector)
	if err != nil {
		return Rule{}, fmt.Errorf("to: %w", err)
	}
	ports, err := normalizePorts(rule.Ports)
	if err != nil {
		return Rule{}, err
	}
	normalized.From = &Endpoint{Selector: from}
	normalized.To = &Endpoint{Selector: to}
	normalized.Ports = ports
	return normalized, nil
}

// NormalizePolicy validates and canonicalizes the policy portion of a live
// topology snapshot without requiring callers to place network addresses in
// the audit-only Config schema.
func NormalizePolicy(input Policy) (Policy, error) {
	if len(input.Rules) > MaxRules {
		return Policy{}, fmt.Errorf("policy.rules may contain at most %d entries", MaxRules)
	}
	if input.DefaultAction != "allow" && input.DefaultAction != "deny" {
		return Policy{}, errors.New("policy.default_action must be allow or deny")
	}

	rules := make([]Rule, 0, len(input.Rules))
	for index, rule := range input.Rules {
		normalized, err := normalizeRule(rule)
		if err != nil {
			return Policy{}, fmt.Errorf("policy.rules[%d]: %w", index, err)
		}
		rules = append(rules, normalized)
	}
	return Policy{DefaultAction: input.DefaultAction, Rules: rules}, nil
}

func normalizePorts(ports []string) ([]string, error) {
	if len(ports) > 64 {
		return nil, errors.New("ports may contain at most 64 entries")
	}
	normalized := make([]string, 0, len(ports))
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		parts := strings.Split(port, "/")
		if len(parts) > 2 || len(parts) == 0 {
			return nil, errors.New("ports contains an invalid entry")
		}
		number, err := strconv.Atoi(parts[0])
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("ports contains an invalid entry")
		}
		canonical := strconv.Itoa(number)
		if len(parts) == 2 {
			protocol := strings.ToLower(parts[1])
			if protocol != "tcp" && protocol != "udp" {
				return nil, errors.New("ports contains an invalid entry")
			}
			canonical += "/" + protocol
		}
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("ports contains a duplicate entry")
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)
	return normalized, nil
}
