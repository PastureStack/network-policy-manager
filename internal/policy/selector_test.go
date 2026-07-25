package policy

import "testing"

func TestSelectorCanonicalizationAndMatching(t *testing.T) {
	t.Parallel()
	canonical, selector, err := parseSelector(" Zone = EAST , tier IN (worker,Web), track!=Canary, owner notin (red,blue) ")
	if err != nil {
		t.Fatal(err)
	}
	want := "owner notin (blue,red),tier in (web,worker),track!=canary,zone=east"
	if canonical != want {
		t.Fatalf("canonical = %q, want %q", canonical, want)
	}
	if !selector.matches(map[string]string{"zone": "east", "tier": "web", "track": "stable", "owner": "green"}) {
		t.Fatal("selector should match")
	}
	if selector.matches(map[string]string{"zone": "east", "tier": "web", "owner": "green"}) {
		t.Fatal("negative comparison must not match a missing key")
	}
	if selector.matches(map[string]string{"zone": "east", "tier": "web", "track": "stable"}) {
		t.Fatal("notin must not match a missing key")
	}
}

func TestSelectorExistsAndEquality(t *testing.T) {
	t.Parallel()
	_, selector, err := parseSelector("enabled,track==stable")
	if err != nil {
		t.Fatal(err)
	}
	if !selector.matches(map[string]string{"enabled": "", "track": "stable"}) {
		t.Fatal("selector should match")
	}
	if selector.matches(map[string]string{"enabled": "", "track": "other"}) {
		t.Fatal("selector should not match")
	}
}

func TestInvalidSelectors(t *testing.T) {
	t.Parallel()
	cases := []string{
		"", "a,", ",a", "a,,b", "a in ()", "a in (x,x)", "a in ((x))", "a in (x", "a > x",
		"a=x,a==x", "a=", "a in (x,?)", "bad key=x",
	}
	for _, input := range cases {
		input := input
		t.Run(input, func(t *testing.T) {
			if _, _, err := parseSelector(input); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, _, err := parseSelector(string(make([]byte, 1025))); err == nil {
		t.Fatal("expected length error")
	}
	clauses := "a"
	for index := 0; index < 32; index++ {
		clauses += ",a" + string(rune('b'+index))
	}
	if _, _, err := parseSelector(clauses); err == nil {
		t.Fatal("expected clause limit error")
	}
}

func TestMatchSelectorNormalizesLabels(t *testing.T) {
	t.Parallel()
	matched, err := MatchSelector("Tier in (WEB,worker)", map[string]string{"TIER": "Web"})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected selector to match normalized labels")
	}
}
