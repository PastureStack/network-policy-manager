package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const reconcileTimeout = 10 * time.Second

type SnapshotSource interface {
	Snapshot(context.Context) (Snapshot, error)
}

type Manager struct {
	Source        SnapshotSource
	Backend       FirewallBackend
	PollInterval  time.Duration
	FailOpenAfter time.Duration
	Version       string
	Logger        *log.Logger

	mu          sync.RWMutex
	status      PublicStatus
	lastPlan    FirewallPlan
	havePlan    bool
	failures    atomic.Uint64
	appliedHash string
}

func (manager *Manager) Run(ctx context.Context) error {
	if manager.Source == nil || manager.Backend == nil {
		return errors.New("manager dependencies are incomplete")
	}
	if manager.PollInterval < time.Second {
		return errors.New("poll interval must be at least one second")
	}
	if manager.FailOpenAfter < manager.PollInterval {
		return errors.New("fail-open interval must be at least one poll interval")
	}
	if manager.Logger == nil {
		manager.Logger = log.New(io.Discard, "", 0)
	}

	manager.mu.Lock()
	manager.status.Status = "starting"
	manager.status.Version = manager.Version
	manager.mu.Unlock()

	manager.reconcile(ctx)
	ticker := time.NewTicker(manager.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			manager.reconcile(ctx)
		}
	}
}

func (manager *Manager) reconcile(parent context.Context) {
	now := time.Now().UTC()
	manager.mu.Lock()
	manager.status.LastAttempt = now
	manager.mu.Unlock()

	// A short polling interval must not also shorten the complete metadata
	// transaction. The topology endpoint can briefly take several seconds while
	// services transition, especially on a multi-host deployment.
	ctx, cancel := context.WithTimeout(parent, reconcileTimeout)
	defer cancel()

	snapshot, err := manager.Source.Snapshot(ctx)
	if err != nil {
		manager.recordFailure(now)
		return
	}
	plan, err := Compile(snapshot)
	if err != nil {
		manager.recordFailure(now)
		return
	}
	if plan.Digest != manager.appliedHash {
		if err := manager.Backend.Apply(ctx, plan); err != nil {
			manager.recordFailure(now)
			return
		}
		manager.appliedHash = plan.Digest
		manager.Logger.Printf(
			"applied policy=%s workloads=%d local=%d rules=%d",
			plan.Digest,
			plan.WorkloadCount,
			plan.LocalWorkloadCount,
			len(plan.Rules),
		)
	}

	manager.mu.Lock()
	manager.havePlan = true
	manager.lastPlan = plan
	manager.status = PublicStatus{
		Status:             "ready",
		Version:            manager.Version,
		PolicySHA256:       plan.Digest,
		LastSuccess:        now,
		LastAttempt:        now,
		WorkloadCount:      plan.WorkloadCount,
		LocalWorkloadCount: plan.LocalWorkloadCount,
		PolicyRuleCount:    plan.PolicyRuleCount,
		FirewallRuleCount:  len(plan.Rules),
		ZeroMatchCount:     plan.ZeroMatchCount,
		FailureCount:       manager.failures.Load(),
		FailOpen:           false,
	}
	manager.mu.Unlock()
}

func (manager *Manager) recordFailure(now time.Time) {
	failures := manager.failures.Add(1)
	manager.mu.Lock()
	manager.status.FailureCount = failures
	manager.status.LastAttempt = now
	if manager.status.Status == "starting" {
		manager.status.Status = "degraded"
	} else if manager.status.Status == "ready" {
		manager.status.Status = "degraded"
	}
	lastSuccess := manager.status.LastSuccess
	havePlan := manager.havePlan
	alreadyOpen := manager.status.FailOpen
	previous := manager.lastPlan
	manager.mu.Unlock()

	if !havePlan || alreadyOpen || lastSuccess.IsZero() || now.Sub(lastSuccess) < manager.FailOpenAfter {
		return
	}
	plan, err := FailOpenPlan(previous)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := manager.Backend.Apply(ctx, plan); err != nil {
		return
	}
	manager.appliedHash = plan.Digest
	manager.mu.Lock()
	manager.status.Status = "degraded"
	manager.status.PolicySHA256 = plan.Digest
	manager.status.FirewallRuleCount = 0
	manager.status.FailOpen = true
	manager.mu.Unlock()
	manager.Logger.Printf("metadata stale; applied bounded fail-open policy=%s", plan.Digest)
}

func (manager *Manager) Status() PublicStatus {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.status
}

func (manager *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(response, "{\"status\":\"ok\"}\n")
	})
	mux.HandleFunc("/readyz", func(response http.ResponseWriter, _ *http.Request) {
		status := manager.Status()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		if status.Status != "ready" || status.FailOpen {
			response.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(response).Encode(status)
	})
	mux.HandleFunc("/status", func(response http.ResponseWriter, _ *http.Request) {
		status := manager.Status()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(status)
	})
	return mux
}
