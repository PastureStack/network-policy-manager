package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validDocument = `{
  "schema":"pasturestack.network-policy-snapshot/v1",
  "local_host_id":"host-a",
  "stacks":[{"id":"application","system":false}],
  "services":[],
  "workloads":[{"id":"workload-a","host_id":"host-a","stack_id":"application"}],
  "policy":{"default_action":"deny","rules":[]}
}`

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunFromStandardInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, strings.NewReader(validDocument), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema": "pasturestack.network-policy-plan/v1"`) {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestRunFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(validDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--file", path}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestRunVersionAndArgumentErrors(t *testing.T) {
	oldVersion := version
	version = "test-version"
	t.Cleanup(func() { version = oldVersion })
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 || strings.TrimSpace(stdout.String()) != "test-version" {
		t.Fatalf("version code=%d output=%q", code, stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"extra"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("positional code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--unknown"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("flag code=%d", code)
	}
}

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		input  string
		writer errorWriter
		want   int
	}{
		{name: "missing file", args: []string{"--file", filepath.Join(t.TempDir(), "missing.json")}, want: 1},
		{name: "decode", input: "{", want: 1},
		{name: "validation", input: `{"schema":"pasturestack.network-policy-snapshot/v1","local_host_id":"host-a","stacks":[],"services":[],"workloads":[],"policy":{"default_action":"deny","rules":[]}}`, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(test.args, strings.NewReader(test.input), &stdout, &stderr); code != test.want {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
		})
	}
	var stderr bytes.Buffer
	if code := run(nil, strings.NewReader(validDocument), errorWriter{}, &stderr); code != 1 {
		t.Fatalf("writer code=%d", code)
	}
}
