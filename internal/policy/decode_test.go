package policy

import (
	"errors"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestDecodeStrictJSON(t *testing.T) {
	t.Parallel()
	valid := `{"schema":"pasturestack.network-policy-snapshot/v1","local_host_id":"host-a","stacks":[],"services":[],"workloads":[],"policy":{"default_action":"deny","rules":[]}}`
	if _, err := Decode(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`{"schema":"one","schema":"two"}`,
		`{"unknown":true}`,
		valid + valid,
		`{"schema":`,
	}
	for _, input := range cases {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("expected error for %q", input)
		}
	}
	if _, err := Decode(strings.NewReader(strings.Repeat(" ", MaxInputBytes+1))); err == nil {
		t.Fatal("expected size error")
	}
	if _, err := Decode(failingReader{}); err == nil {
		t.Fatal("expected read error")
	}
}

func TestDuplicateNestedField(t *testing.T) {
	t.Parallel()
	input := `{"schema":"x","policy":{"default_action":"deny","default_action":"allow"}}`
	if _, err := Decode(strings.NewReader(input)); err == nil {
		t.Fatal("expected duplicate-field error")
	}
}
