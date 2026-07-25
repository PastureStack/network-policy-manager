package policy

const (
	InputSchema = "pasturestack.network-policy-snapshot/v1"
	PlanSchema  = "pasturestack.network-policy-plan/v1"

	MaxInputBytes = 2 << 20
	MaxStacks     = 256
	MaxServices   = 1024
	MaxWorkloads  = 4096
	MaxRules      = 256
)

type Config struct {
	Schema      string     `json:"schema"`
	LocalHostID string     `json:"local_host_id"`
	Stacks      []Stack    `json:"stacks"`
	Services    []Service  `json:"services"`
	Workloads   []Workload `json:"workloads"`
	Policy      Policy     `json:"policy"`
}

type Stack struct {
	ID     string `json:"id"`
	System bool   `json:"system"`
}

type Service struct {
	ID               string            `json:"id"`
	StackID          string            `json:"stack_id"`
	Labels           map[string]string `json:"labels,omitempty"`
	PrimaryServiceID string            `json:"primary_service_id,omitempty"`
	Links            []string          `json:"links,omitempty"`
}

type Workload struct {
	ID        string            `json:"id"`
	HostID    string            `json:"host_id"`
	StackID   string            `json:"stack_id"`
	ServiceID string            `json:"service_id,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Links     []string          `json:"links,omitempty"`
}

type Policy struct {
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	Within  string    `json:"within,omitempty"`
	Between *Between  `json:"between,omitempty"`
	From    *Endpoint `json:"from,omitempty"`
	To      *Endpoint `json:"to,omitempty"`
	Ports   []string  `json:"ports,omitempty"`
	Action  string    `json:"action"`
}

type Between struct {
	Selector string `json:"selector,omitempty"`
	GroupBy  string `json:"group_by,omitempty"`
}

type Endpoint struct {
	Selector string `json:"selector"`
}

type Plan struct {
	Schema           string      `json:"schema"`
	NormalizedSHA256 string      `json:"normalized_sha256"`
	DefaultAction    string      `json:"default_action"`
	Inventory        Inventory   `json:"inventory"`
	Rules            RuleCounts  `json:"rules"`
	Compilation      Compilation `json:"compilation"`
	Safeguards       Safeguards  `json:"safeguards"`
}

type Inventory struct {
	StackCount             int `json:"stack_count"`
	ServiceCount           int `json:"service_count"`
	WorkloadCount          int `json:"workload_count"`
	LocalWorkloadCount     int `json:"local_workload_count"`
	SystemWorkloadCount    int `json:"system_workload_count"`
	NonSystemWorkloadCount int `json:"non_system_workload_count"`
}

type RuleCounts struct {
	Total           int `json:"total"`
	Allow           int `json:"allow"`
	Deny            int `json:"deny"`
	WithinStack     int `json:"within_stack"`
	WithinService   int `json:"within_service"`
	WithinLinked    int `json:"within_linked"`
	BetweenSelector int `json:"between_selector"`
	BetweenGroupBy  int `json:"between_group_by"`
	FromTo          int `json:"from_to"`
}

type Compilation struct {
	EstimatedRelationships int64 `json:"estimated_relationships"`
	EstimatedPortScopes    int64 `json:"estimated_port_scopes"`
	LabelGroups            int   `json:"label_groups"`
	RulesWithZeroMatches   int   `json:"rules_with_zero_matches"`
}

type Safeguards struct {
	Mode                    string `json:"mode"`
	AppliesHostChanges      bool   `json:"applies_host_changes"`
	ReadsMetadata           bool   `json:"reads_metadata"`
	AcceptsNetworkAddresses bool   `json:"accepts_network_addresses"`
	AcceptsSecretMaterial   bool   `json:"accepts_secret_material"`
	EmitsIdentifiers        bool   `json:"emits_identifiers"`
	ProductionReady         bool   `json:"production_ready"`
}
