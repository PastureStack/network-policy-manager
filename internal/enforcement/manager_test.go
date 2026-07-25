package enforcement

import (
	"context"
	"errors"
	"testing"
	"time"
)

type deadlineSource struct {
	remaining time.Duration
}

func (source *deadlineSource) Snapshot(ctx context.Context) (Snapshot, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return Snapshot{}, errors.New("missing reconcile deadline")
	}
	source.remaining = time.Until(deadline)
	return Snapshot{}, errors.New("test source failure")
}

func TestReconcileTimeoutDoesNotShrinkWithPollInterval(t *testing.T) {
	source := &deadlineSource{}
	manager := &Manager{
		Source:        source,
		PollInterval:  time.Second,
		FailOpenAfter: 30 * time.Second,
	}

	manager.reconcile(context.Background())

	if source.remaining < 9*time.Second {
		t.Fatalf("reconcile deadline was too short: %s", source.remaining)
	}
	if source.remaining > reconcileTimeout {
		t.Fatalf("reconcile deadline exceeded configured timeout: %s", source.remaining)
	}
}
