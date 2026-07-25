package enforcement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/PastureStack/network-policy-manager/internal/policy"
)

type MetadataClient struct {
	BaseURL string
	Client  *http.Client
}

type metadataHost struct {
	UUID string `json:"uuid"`
}

type metadataNetwork struct {
	UUID                string          `json:"uuid"`
	Default             bool            `json:"is_default"`
	DefaultPolicyAction string          `json:"default_policy_action"`
	Metadata            json.RawMessage `json:"metadata"`
	Policy              json.RawMessage `json:"policy"`
}

type metadataStack struct {
	UUID     string            `json:"uuid"`
	Name     string            `json:"name"`
	System   bool              `json:"system"`
	Services []metadataService `json:"services"`
}

type metadataService struct {
	UUID               string              `json:"uuid"`
	Name               string              `json:"name"`
	StackUUID          string              `json:"stack_uuid"`
	StackName          string              `json:"stack_name"`
	System             bool                `json:"system"`
	PrimaryServiceName string              `json:"primary_service_name"`
	Labels             map[string]string   `json:"labels"`
	Links              map[string]string   `json:"links"`
	Containers         []metadataContainer `json:"containers"`
}

type metadataContainer struct {
	UUID        string            `json:"uuid"`
	HostUUID    string            `json:"host_uuid"`
	StackUUID   string            `json:"stack_uuid"`
	ServiceUUID string            `json:"service_uuid"`
	NetworkUUID string            `json:"network_uuid"`
	PrimaryIP   string            `json:"primary_ip"`
	State       string            `json:"state"`
	System      bool              `json:"system"`
	Labels      map[string]string `json:"labels"`
	Links       []string          `json:"links"`
}

type rawRule struct {
	Within  string       `json:"within"`
	Between *rawBetween  `json:"between"`
	From    *rawEndpoint `json:"from"`
	To      *rawEndpoint `json:"to"`
	Ports   []string     `json:"ports"`
	Action  string       `json:"action"`
}

type rawBetween struct {
	Selector   string `json:"selector"`
	GroupBy    string `json:"groupBy"`
	GroupByAlt string `json:"group_by"`
}

type rawEndpoint struct {
	Selector string `json:"selector"`
}

func NewMetadataClient(baseURL string) *MetadataClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultMetadataURL
	}
	return &MetadataClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:                 nil,
				DisableCompression:    true,
				MaxIdleConns:          4,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}
}

func (client *MetadataClient) Snapshot(ctx context.Context) (Snapshot, error) {
	var host metadataHost
	var networks []metadataNetwork
	var stacks []metadataStack
	if err := client.getJSON(ctx, "self/host", &host); err != nil {
		return Snapshot{}, fmt.Errorf("read local host metadata: %w", err)
	}
	if host.UUID == "" {
		return Snapshot{}, errors.New("local host metadata is incomplete")
	}
	if err := client.getJSON(ctx, "networks", &networks); err != nil {
		return Snapshot{}, fmt.Errorf("read network metadata: %w", err)
	}
	if err := client.getJSON(ctx, "stacks", &stacks); err != nil {
		return Snapshot{}, fmt.Errorf("read topology metadata: %w", err)
	}
	return buildSnapshot(host, networks, stacks)
}

func (client *MetadataClient) getJSON(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.BaseURL+"/"+path, nil)
	if err != nil {
		return errors.New("construct metadata request")
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.Client.Do(request)
	if err != nil {
		return errors.New("metadata request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata returned HTTP %d", response.StatusCode)
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return errors.New("metadata response is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("metadata response contains trailing content")
	}
	return nil
}

func buildSnapshot(host metadataHost, networks []metadataNetwork, stacks []metadataStack) (Snapshot, error) {
	network, subnet, err := selectDefaultNetwork(networks)
	if err != nil {
		return Snapshot{}, err
	}
	normalizedPolicy, err := parsePolicy(network.DefaultPolicyAction, network.Policy)
	if err != nil {
		return Snapshot{}, err
	}

	if len(stacks) > policy.MaxStacks {
		return Snapshot{}, fmt.Errorf("topology contains more than %d stacks", policy.MaxStacks)
	}

	serviceVariantsByID := make(map[string][]metadataService)
	serviceByID := make(map[string]metadataService)
	serviceByPath := make(map[string]string)
	servicePrimary := make(map[string]string)
	stackSystem := make(map[string]bool)
	serviceCount := 0
	for _, stack := range stacks {
		if stack.UUID == "" {
			return Snapshot{}, errors.New("topology contains a stack without an identifier")
		}
		stackSystem[stack.UUID] = stack.System
		for _, service := range stack.Services {
			serviceCount++
			if serviceCount > policy.MaxServices {
				return Snapshot{}, fmt.Errorf("topology contains more than %d services", policy.MaxServices)
			}
			if service.UUID == "" {
				return Snapshot{}, errors.New("topology contains a service without an identifier")
			}
			if service.StackUUID == "" {
				service.StackUUID = stack.UUID
			}
			if service.StackName == "" {
				service.StackName = stack.Name
			}
			serviceVariantsByID[service.UUID] = append(serviceVariantsByID[service.UUID], service)
			path := servicePath(service.StackName, service.Name)
			if existing, ok := serviceByPath[path]; ok && existing != service.UUID {
				return Snapshot{}, errors.New("topology contains a conflicting service path")
			}
			serviceByPath[path] = service.UUID
		}
	}
	serviceIDs := make([]string, 0, len(serviceVariantsByID))
	for id, variants := range serviceVariantsByID {
		service, canonicalErr := canonicalizeServiceVariants(variants)
		if canonicalErr != nil {
			return Snapshot{}, canonicalErr
		}
		serviceByID[id] = service
		serviceIDs = append(serviceIDs, id)
	}
	sort.Strings(serviceIDs)
	for id, service := range serviceByID {
		primary := id
		if service.PrimaryServiceName != "" && !strings.EqualFold(service.PrimaryServiceName, service.Name) {
			if candidate, ok := serviceByPath[servicePath(service.StackName, service.PrimaryServiceName)]; ok {
				primary = candidate
			}
		}
		servicePrimary[id] = primary
	}

	serviceLinks := make(map[string][]string)
	for id, variants := range serviceVariantsByID {
		source := servicePrimary[id]
		for _, service := range variants {
			for key, value := range service.Links {
				target, ok := resolveServiceLink(service.StackName, key, serviceByPath)
				if !ok && value != "" {
					target, ok = resolveServiceLink(service.StackName, value, serviceByPath)
				}
				if ok {
					serviceLinks[source] = appendUnique(serviceLinks[source], servicePrimary[target])
				}
			}
		}
	}

	workloads := make([]Workload, 0)
	workloadByID := make(map[string]Workload)
	containerLinks := make(map[string][]string)
	for _, serviceID := range serviceIDs {
		service := serviceByID[serviceID]
		for _, container := range service.Containers {
			if container.UUID == "" || container.HostUUID == "" || container.State != "running" {
				continue
			}
			if container.NetworkUUID != network.UUID || container.PrimaryIP == "" {
				continue
			}
			address, parseErr := netip.ParseAddr(container.PrimaryIP)
			if parseErr != nil || !address.Is4() || !subnet.Contains(address) {
				continue
			}

			labels := normalizeRuntimeLabels(service.Labels)
			for key, value := range normalizeRuntimeLabels(container.Labels) {
				labels[key] = value
			}
			stackID := service.StackUUID
			if stackID == "" {
				stackID = container.StackUUID
			}
			workload := Workload{
				ID:               container.UUID,
				IP:               address,
				HostID:           container.HostUUID,
				StackID:          stackID,
				ServiceID:        service.UUID,
				PrimaryServiceID: servicePrimary[service.UUID],
				System:           stackSystem[stackID] || service.System || container.System,
				Labels:           labels,
			}
			if existing, duplicate := workloadByID[workload.ID]; duplicate {
				if !sameWorkloadIdentity(existing, workload) {
					return Snapshot{}, errors.New("topology contains conflicting views of a workload")
				}
			} else {
				if len(workloadByID) >= policy.MaxWorkloads {
					return Snapshot{}, fmt.Errorf("topology contains more than %d eligible workloads", policy.MaxWorkloads)
				}
				workloadByID[workload.ID] = workload
			}
			for _, target := range container.Links {
				if target != "" {
					containerLinks[container.UUID] = appendUnique(containerLinks[container.UUID], target)
				}
			}
		}
	}
	for _, workload := range workloadByID {
		workloads = append(workloads, workload)
	}

	sort.Slice(workloads, func(i, j int) bool {
		return workloads[i].IP.Less(workloads[j].IP)
	})
	sortStringMapValues(serviceLinks)
	sortStringMapValues(containerLinks)

	return Snapshot{
		Subnet:         subnet,
		LocalHostID:    host.UUID,
		Workloads:      workloads,
		ServiceLinks:   serviceLinks,
		ContainerLinks: containerLinks,
		Policy:         normalizedPolicy,
	}, nil
}

func canonicalizeServiceVariants(variants []metadataService) (metadataService, error) {
	if len(variants) == 0 {
		return metadataService{}, errors.New("topology contains an empty service group")
	}
	variants = append([]metadataService(nil), variants...)
	sort.SliceStable(variants, func(i, j int) bool {
		leftPrimary := strings.EqualFold(variants[i].Name, variants[i].PrimaryServiceName)
		rightPrimary := strings.EqualFold(variants[j].Name, variants[j].PrimaryServiceName)
		if leftPrimary != rightPrimary {
			return leftPrimary
		}
		return servicePath(variants[i].StackName, variants[i].Name) <
			servicePath(variants[j].StackName, variants[j].Name)
	})

	canonical := variants[0]
	canonical.Containers = nil
	containers := make(map[string]metadataContainer)
	for _, variant := range variants {
		if variant.UUID != canonical.UUID || variant.StackUUID != canonical.StackUUID {
			return metadataService{}, errors.New("topology contains a conflicting shared service identifier")
		}
		canonical.System = canonical.System || variant.System
		for _, container := range variant.Containers {
			if container.UUID == "" {
				continue
			}
			if existing, ok := containers[container.UUID]; ok {
				merged, err := mergeContainerViews(existing, container)
				if err != nil {
					return metadataService{}, err
				}
				containers[container.UUID] = merged
			} else {
				containers[container.UUID] = container
			}
		}
	}
	containerIDs := make([]string, 0, len(containers))
	for id := range containers {
		containerIDs = append(containerIDs, id)
	}
	sort.Strings(containerIDs)
	for _, id := range containerIDs {
		canonical.Containers = append(canonical.Containers, containers[id])
	}
	return canonical, nil
}

func mergeContainerViews(existing, candidate metadataContainer) (metadataContainer, error) {
	fields := []struct {
		existing  *string
		candidate string
	}{
		{&existing.HostUUID, candidate.HostUUID},
		{&existing.StackUUID, candidate.StackUUID},
		{&existing.ServiceUUID, candidate.ServiceUUID},
		{&existing.NetworkUUID, candidate.NetworkUUID},
		{&existing.PrimaryIP, candidate.PrimaryIP},
	}
	for _, field := range fields {
		if *field.existing == "" {
			*field.existing = field.candidate
		} else if field.candidate != "" && *field.existing != field.candidate {
			return metadataContainer{}, errors.New("topology contains conflicting views of a workload")
		}
	}
	if existing.State == "" || candidate.State == "running" {
		existing.State = candidate.State
	}
	existing.System = existing.System || candidate.System
	if existing.Labels == nil {
		existing.Labels = make(map[string]string)
	}
	for key, value := range candidate.Labels {
		if current, ok := existing.Labels[key]; ok && current != value {
			return metadataContainer{}, errors.New("topology contains conflicting workload labels")
		}
		existing.Labels[key] = value
	}
	for _, target := range candidate.Links {
		if target != "" {
			existing.Links = appendUnique(existing.Links, target)
		}
	}
	sort.Strings(existing.Links)
	return existing, nil
}

func sameWorkloadIdentity(left, right Workload) bool {
	if left.ID != right.ID ||
		left.IP != right.IP ||
		left.HostID != right.HostID ||
		left.StackID != right.StackID ||
		left.ServiceID != right.ServiceID ||
		left.PrimaryServiceID != right.PrimaryServiceID ||
		left.System != right.System ||
		len(left.Labels) != len(right.Labels) {
		return false
	}
	for key, value := range left.Labels {
		if right.Labels[key] != value {
			return false
		}
	}
	return true
}

func selectDefaultNetwork(networks []metadataNetwork) (metadataNetwork, netip.Prefix, error) {
	var selected *metadataNetwork
	var selectedSubnet netip.Prefix
	for index := range networks {
		network := &networks[index]
		if !network.Default {
			continue
		}
		subnet, err := extractBridgeSubnet(network.Metadata)
		if err != nil {
			continue
		}
		if selected != nil {
			return metadataNetwork{}, netip.Prefix{}, errors.New("multiple eligible default networks were reported")
		}
		selected = network
		selectedSubnet = subnet
	}
	if selected == nil {
		return metadataNetwork{}, netip.Prefix{}, errors.New("no eligible default network was reported")
	}
	return *selected, selectedSubnet, nil
}

func extractBridgeSubnet(raw json.RawMessage) (netip.Prefix, error) {
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return netip.Prefix{}, errors.New("network metadata is invalid")
	}
	config, ok := document["cniConfig"].(map[string]any)
	if !ok || len(config) == 0 {
		return netip.Prefix{}, errors.New("network metadata has no CNI configuration")
	}
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		properties, ok := config[key].(map[string]any)
		if !ok {
			continue
		}
		text, ok := properties["bridgeSubnet"].(string)
		if !ok {
			continue
		}
		subnet, err := netip.ParsePrefix(text)
		if err == nil && subnet.Addr().Is4() {
			return subnet.Masked(), nil
		}
	}
	return netip.Prefix{}, errors.New("network metadata has no valid bridge subnet")
}

func parsePolicy(defaultAction string, raw json.RawMessage) (policy.Policy, error) {
	if defaultAction == "" {
		defaultAction = "allow"
	}
	var rules []policy.Rule
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null")) {
		var documents []json.RawMessage
		if err := json.Unmarshal(trimmed, &documents); err != nil {
			return policy.Policy{}, errors.New("network policy is not an array")
		}
		for index, document := range documents {
			document = bytes.TrimSpace(document)
			if len(document) > 0 && document[0] == '"' {
				var encoded string
				if err := json.Unmarshal(document, &encoded); err != nil {
					return policy.Policy{}, fmt.Errorf("network policy rule %d is invalid", index)
				}
				document = []byte(encoded)
			}
			var input rawRule
			decoder := json.NewDecoder(bytes.NewReader(document))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				return policy.Policy{}, fmt.Errorf("network policy rule %d is invalid", index)
			}
			rule := policy.Rule{
				Within: input.Within,
				Ports:  input.Ports,
				Action: input.Action,
			}
			if input.Between != nil {
				groupBy := input.Between.GroupBy
				if groupBy == "" {
					groupBy = input.Between.GroupByAlt
				}
				rule.Between = &policy.Between{Selector: input.Between.Selector, GroupBy: groupBy}
			}
			if input.From != nil {
				rule.From = &policy.Endpoint{Selector: input.From.Selector}
			}
			if input.To != nil {
				rule.To = &policy.Endpoint{Selector: input.To.Selector}
			}
			rules = append(rules, rule)
		}
	}
	normalized, err := policy.NormalizePolicy(policy.Policy{DefaultAction: defaultAction, Rules: rules})
	if err != nil {
		return policy.Policy{}, fmt.Errorf("network policy validation failed: %w", err)
	}
	return normalized, nil
}

func normalizeRuntimeLabels(labels map[string]string) map[string]string {
	normalized := make(map[string]string, len(labels))
	for key, value := range labels {
		normalized[strings.ToLower(key)] = strings.ToLower(value)
	}
	return normalized
}

func servicePath(stack, service string) string {
	return strings.ToLower(strings.TrimSpace(stack) + "/" + strings.TrimSpace(service))
}

func resolveServiceLink(stackName, candidate string, serviceByPath map[string]string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	if strings.Count(candidate, "/") == 0 {
		candidate = stackName + "/" + candidate
	}
	id, ok := serviceByPath[strings.ToLower(candidate)]
	return id, ok
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortStringMapValues(values map[string][]string) {
	for key := range values {
		sort.Strings(values[key])
	}
}
