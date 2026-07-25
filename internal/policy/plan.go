package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type compiledWorkload struct {
	workload Workload
	labels   map[string]string
	system   bool
	root     string
}

type compiler struct {
	config                 normalizedConfig
	workloads              []compiledWorkload
	withinStackCount       int64
	withinServiceCount     int64
	withinLinkedCount      int64
	localWorkloadCount     int
	systemWorkloadCount    int
	nonSystemWorkloadCount int
}

func BuildPlan(config Config) (Plan, error) {
	normalized, err := normalize(config)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return Plan{}, fmt.Errorf("encode normalized policy snapshot: %w", err)
	}
	digest := sha256.Sum256(encoded)

	compiled := newCompiler(normalized)
	ruleCounts := RuleCounts{Total: len(normalized.Policy.Rules)}
	compilation := Compilation{}
	for _, rule := range normalized.Policy.Rules {
		if rule.Action == "allow" {
			ruleCounts.Allow++
		} else {
			ruleCounts.Deny++
		}
		var relationships int64
		switch {
		case rule.Within == "stack":
			ruleCounts.WithinStack++
			relationships = compiled.withinStackCount
		case rule.Within == "service":
			ruleCounts.WithinService++
			relationships = compiled.withinServiceCount
		case rule.Within == "linked":
			ruleCounts.WithinLinked++
			relationships = compiled.withinLinkedCount
		case rule.Between != nil && rule.Between.Selector != "":
			ruleCounts.BetweenSelector++
			relationships = compiled.selectorRelationships(rule.Between.Selector)
		case rule.Between != nil:
			ruleCounts.BetweenGroupBy++
			var groups int
			relationships, groups = compiled.groupRelationships(rule.Between.GroupBy)
			compilation.LabelGroups += groups
		default:
			ruleCounts.FromTo++
			relationships = compiled.fromToRelationships(rule.From.Selector, rule.To.Selector)
			scopes := len(rule.Ports)
			if scopes == 0 {
				scopes = 1
			}
			compilation.EstimatedPortScopes += relationships * int64(scopes)
		}
		compilation.EstimatedRelationships += relationships
		if relationships == 0 {
			compilation.RulesWithZeroMatches++
		}
	}

	return Plan{
		Schema:           PlanSchema,
		NormalizedSHA256: hex.EncodeToString(digest[:]),
		DefaultAction:    normalized.Policy.DefaultAction,
		Inventory: Inventory{
			StackCount: len(normalized.Stacks), ServiceCount: len(normalized.Services), WorkloadCount: len(normalized.Workloads),
			LocalWorkloadCount: compiled.localWorkloadCount, SystemWorkloadCount: compiled.systemWorkloadCount,
			NonSystemWorkloadCount: compiled.nonSystemWorkloadCount,
		},
		Rules:       ruleCounts,
		Compilation: compilation,
		Safeguards: Safeguards{
			Mode: "audit-only", AppliesHostChanges: false, ReadsMetadata: false,
			AcceptsNetworkAddresses: false, AcceptsSecretMaterial: false, EmitsIdentifiers: false, ProductionReady: false,
		},
	}, nil
}

func newCompiler(config normalizedConfig) compiler {
	stackSystem := make(map[string]bool, len(config.Stacks))
	for _, stack := range config.Stacks {
		stackSystem[stack.ID] = stack.System
	}
	serviceByID := make(map[string]Service, len(config.Services))
	rootByService := make(map[string]string, len(config.Services))
	for _, service := range config.Services {
		serviceByID[service.ID] = service
		root := service.ID
		if service.PrimaryServiceID != "" {
			root = service.PrimaryServiceID
		}
		rootByService[service.ID] = root
	}

	compiled := compiler{config: config}
	stackAll := make(map[string]int64)
	stackLocal := make(map[string]int64)
	serviceAll := make(map[string]int64)
	serviceLocal := make(map[string]int64)
	workloadsByRoot := make(map[string][]string)
	workloadSystem := make(map[string]bool, len(config.Workloads))
	workloadLocal := make(map[string]bool, len(config.Workloads))

	for _, workload := range config.Workloads {
		labels := make(map[string]string)
		root := ""
		if workload.ServiceID != "" {
			service := serviceByID[workload.ServiceID]
			for key, value := range service.Labels {
				labels[key] = value
			}
			root = rootByService[workload.ServiceID]
		}
		for key, value := range workload.Labels {
			labels[key] = value
		}
		system := stackSystem[workload.StackID]
		local := workload.HostID == config.LocalHostID
		if local {
			compiled.localWorkloadCount++
		}
		if system {
			compiled.systemWorkloadCount++
		} else {
			compiled.nonSystemWorkloadCount++
			stackAll[workload.StackID]++
			if local {
				stackLocal[workload.StackID]++
			}
			if root != "" {
				serviceAll[root]++
				workloadsByRoot[root] = append(workloadsByRoot[root], workload.ID)
				if local {
					serviceLocal[root]++
				}
			}
		}
		workloadSystem[workload.ID] = system
		workloadLocal[workload.ID] = local
		compiled.workloads = append(compiled.workloads, compiledWorkload{workload: workload, labels: labels, system: system, root: root})
	}
	for key, local := range stackLocal {
		compiled.withinStackCount += local * stackAll[key]
	}
	for key, local := range serviceLocal {
		compiled.withinServiceCount += local * serviceAll[key]
	}

	serviceLinks := make(map[string]map[string]struct{})
	for _, service := range config.Services {
		from := rootByService[service.ID]
		for _, link := range service.Links {
			to := rootByService[link]
			if from == to {
				continue
			}
			addLink(serviceLinks, from, to)
			addLink(serviceLinks, to, from)
		}
	}
	workloadLinks := make(map[string]map[string]struct{})
	for _, workload := range config.Workloads {
		for _, link := range workload.Links {
			addLink(workloadLinks, workload.ID, link)
			addLink(workloadLinks, link, workload.ID)
		}
	}
	for _, destination := range compiled.workloads {
		if destination.system || !workloadLocal[destination.workload.ID] {
			continue
		}
		sources := make(map[string]struct{})
		for source := range workloadLinks[destination.workload.ID] {
			if !workloadSystem[source] {
				sources[source] = struct{}{}
			}
		}
		if destination.root != "" {
			for linkedRoot := range serviceLinks[destination.root] {
				for _, source := range workloadsByRoot[linkedRoot] {
					sources[source] = struct{}{}
				}
			}
		}
		compiled.withinLinkedCount += int64(len(sources))
	}
	return compiled
}

func addLink(index map[string]map[string]struct{}, from, to string) {
	if index[from] == nil {
		index[from] = make(map[string]struct{})
	}
	index[from][to] = struct{}{}
}

func (compiled compiler) selectorRelationships(expression string) int64 {
	_, selector, _ := parseSelector(expression)
	var all, local int64
	for _, workload := range compiled.workloads {
		if workload.system || !selector.matches(workload.labels) {
			continue
		}
		all++
		if workload.workload.HostID == compiled.config.LocalHostID {
			local++
		}
	}
	return all * local
}

func (compiled compiler) groupRelationships(key string) (int64, int) {
	all := make(map[string]int64)
	local := make(map[string]int64)
	for _, workload := range compiled.workloads {
		if workload.system {
			continue
		}
		value, exists := workload.labels[key]
		if !exists {
			continue
		}
		all[value]++
		if workload.workload.HostID == compiled.config.LocalHostID {
			local[value]++
		}
	}
	var relationships int64
	for value, localCount := range local {
		relationships += localCount * all[value]
	}
	return relationships, len(all)
}

func (compiled compiler) fromToRelationships(fromExpression, toExpression string) int64 {
	_, from, _ := parseSelector(fromExpression)
	_, to, _ := parseSelector(toExpression)
	var sources, destinations int64
	for _, workload := range compiled.workloads {
		if workload.system {
			continue
		}
		if from.matches(workload.labels) {
			sources++
		}
		if workload.workload.HostID == compiled.config.LocalHostID && to.matches(workload.labels) {
			destinations++
		}
	}
	return sources * destinations
}
