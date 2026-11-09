package app_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type propagationResult struct {
	Resolvers []struct {
		Name    string              `json:"name"`
		Answers map[string][]string `json:"answers"`
		Error   string              `json:"error"`
	} `json:"resolvers"`
	Disagree []string `json:"disagree"`
}

func runPropagation(t *testing.T, resolvers []app.PublicResolver) (propagationResult, []finding) {
	t.Helper()
	h := start(t, app.Config{
		Net:          app.Net{Resolver: fakeDNS(t, exampleZone, false), PublicResolvers: resolvers},
		CheckTimeout: 500 * time.Millisecond,
	})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "dns_propagation", "target": "example.com"}, nil); code != http.StatusOK {
		t.Fatalf("run dns_propagation: %d", code)
	}
	h.waitSteps(c.ID, 2)
	var raw struct {
		Steps []struct {
			Check  string          `json:"check"`
			Status string          `json:"status"`
			Result json.RawMessage `json:"result"`
		} `json:"steps"`
		Findings []finding `json:"findings"`
	}
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &raw)
	var res propagationResult
	if s := raw.Steps[1]; s.Check != "dns_propagation" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	return res, raw.Findings
}

func TestPropagationAgreesWhenEveryResolverMatches(t *testing.T) {
	res, fs := runPropagation(t, []app.PublicResolver{
		{Name: "One", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "Two", Location: "DE", Address: fakeDNS(t, exampleZone, false)},
	})
	if len(res.Resolvers) != 2 || len(res.Disagree) != 0 || res.Resolvers[0].Answers["MX"][0] != "10 mail.example.com." {
		t.Fatalf("result = %+v", res)
	}
	if !slices.Contains(codes(fs), "dns_propagation_consistent") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestPropagationFlagsResolversThatDisagree(t *testing.T) {
	res, fs := runPropagation(t, []app.PublicResolver{
		{Name: "Updated", Location: "US", Address: fakeDNS(t, movedMX, false)},
		{Name: "Also updated", Location: "SG", Address: fakeDNS(t, movedMX, false)},
		{Name: "Stale", Location: "DE", Address: fakeDNS(t, exampleZone, false)},
		{Name: "Down", Location: "BR", Address: fakeDNS(t, "", true)},
	})
	if !slices.Contains(res.Disagree, "MX") || slices.Contains(res.Disagree, "NS") {
		t.Fatalf("disagree = %v", res.Disagree)
	}
	if res.Resolvers[3].Error == "" {
		t.Fatalf("unreachable resolver has no error: %+v", res.Resolvers[3])
	}
	i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == "dns_propagation_mismatch" })
	if i == -1 || fs[i].Severity != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
	if !slices.Contains(codes(fs), "dns_propagation_unreachable") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestPropagationTreatsDifferingAddressesAsInfo(t *testing.T) {
	// CDNs and geo-DNS legitimately answer A/AAAA differently per region.
	_, fs := runPropagation(t, []app.PublicResolver{
		{Name: "US", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "EU", Location: "DE", Address: fakeDNS(t, zoneFile("geo_eu"), false)},
	})
	for _, f := range fs {
		if f.Code == "dns_propagation_mismatch" {
			t.Fatalf("address differences raised a warning: %+v", f)
		}
	}
	if !slices.Contains(codes(fs), "dns_propagation_addresses_vary") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestChecksAreListedWithTheirOptions(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var list []struct {
		Key   string   `json:"key"`
		Label string   `json:"label"`
		Kinds []string `json:"kinds"`
	}
	h.do("GET", "/api/checks", nil, &list)
	keys := []string{}
	for _, c := range list {
		keys = append(keys, c.Key)
		if c.Label == "" || len(c.Kinds) == 0 {
			t.Errorf("incomplete check %+v", c)
		}
	}
	for _, want := range []string{"dns_lookup", "dns_propagation"} {
		if !slices.Contains(keys, want) {
			t.Errorf("missing %s in %v", want, keys)
		}
	}
}

func TestUnknownOrInvalidOptionsAreRejected(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{
		"check": "dns_lookup", "target": "example.com", "options": map[string]string{"bogus": "1"}}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown option: %d", code)
	}
}

func TestOptionsArePartOfAStepsIdentity(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{
		Resolver:        fakeDNS(t, exampleZone, false),
		PublicResolvers: []app.PublicResolver{{Name: "One", Location: "US", Address: fakeDNS(t, exampleZone, false)}},
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	run := func(opts map[string]string) int {
		return h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "dns_propagation", "target": "example.com", "options": opts}, nil)
	}
	if code := run(map[string]string{"scope": "everything"}); code != http.StatusBadRequest {
		t.Fatalf("invalid choice: %d", code)
	}
	run(map[string]string{"scope": "mail"})
	h.waitSteps(c.ID, 2)
	run(nil) // default scope: all
	h.waitSteps(c.ID, 3)
	run(map[string]string{"scope": "all"}) // same identity as the default run
	steps := h.waitSteps(c.ID, 4)

	if steps[2].ComparedTo != 0 {
		t.Fatalf("an all-scope run was compared to a mail-scope run: %+v", steps[2])
	}
	if steps[3].ComparedTo != steps[2].ID {
		t.Fatalf("explicit default not compared to implicit default: %+v", steps[3])
	}
}

func TestAFailedQueryOnOneResolverIsNotADisagreement(t *testing.T) {
	res, fs := runPropagation(t, []app.PublicResolver{
		{Name: "One", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "TXT refused", Location: "DE", Address: fakeDNS(t, exampleZone, false, dns.TypeTXT)},
	})
	if slices.Contains(res.Disagree, "TXT") || slices.Contains(codes(fs), "dns_propagation_mismatch") {
		t.Fatalf("disagree = %v, findings %v", res.Disagree, codes(fs))
	}
}

func TestTooFewAnswersCannotBeCalledPropagated(t *testing.T) {
	_, fs := runPropagation(t, []app.PublicResolver{
		{Name: "One", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "Down", Location: "DE", Address: fakeDNS(t, "", true)},
	})
	if slices.Contains(codes(fs), "dns_propagation_consistent") || !slices.Contains(codes(fs), "dns_propagation_insufficient") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestNoResolverAnsweringFailsTheStep(t *testing.T) {
	h := start(t, app.Config{
		Net: app.Net{Resolver: fakeDNS(t, exampleZone, false), PublicResolvers: []app.PublicResolver{
			{Name: "Down", Location: "DE", Address: fakeDNS(t, "", true)}}},
		CheckTimeout: 300 * time.Millisecond,
	})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "dns_propagation", "target": "example.com"}, nil)
	if s := h.waitSteps(c.ID, 2)[1]; s.Status != "failed" {
		t.Fatalf("step = %+v", s)
	}
}

func TestANameThatExistsNowhereIsNotPropagated(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false), PublicResolvers: []app.PublicResolver{
		{Name: "One", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "Two", Location: "DE", Address: fakeDNS(t, exampleZone, false)},
	}}})
	c := newCase(h, "nope.test")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "dns_propagation", "target": "nope.test"}, nil)
	h.waitSteps(c.ID, 2)
	fs := codes(h.findings(c.ID).Findings)
	if slices.Contains(fs, "dns_propagation_consistent") || !slices.Contains(fs, "dns_propagation_nxdomain") {
		t.Fatalf("findings = %v", fs)
	}
}

func TestExistenceDifferingBetweenResolversIsAMismatch(t *testing.T) {
	res, fs := runPropagation(t, []app.PublicResolver{
		{Name: "New", Location: "US", Address: fakeDNS(t, exampleZone, false)},
		{Name: "Old", Location: "DE", Address: fakeDNS(t, zoneFile("other"), false)}, // NXDOMAIN for example.com
	})
	if !slices.Contains(res.Disagree, "existence") || !slices.Contains(codes(fs), "dns_propagation_mismatch") {
		t.Fatalf("disagree = %v, findings %v", res.Disagree, codes(fs))
	}
}

func TestFindingsFollowTheLatestRunOfACheckWhateverItsOptions(t *testing.T) {
	stale := fakeDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false), PublicResolvers: []app.PublicResolver{
		{Name: "New", Location: "US", Address: fakeDNS(t, movedMX, false)},
		{Name: "Stale", Location: "DE", Address: stale},
	}}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	run := func(scope string) {
		h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "dns_propagation", "target": "example.com", "options": map[string]string{"scope": scope}}, nil)
	}
	run("all") // MX differs: mismatch
	h.waitSteps(c.ID, 2)
	run("web") // web records agree
	h.waitSteps(c.ID, 3)
	fs := codes(h.findings(c.ID).Findings)
	if slices.Contains(fs, "dns_propagation_mismatch") || !slices.Contains(fs, "dns_propagation_consistent") {
		t.Fatalf("findings should reflect only the latest (web) run: %v", fs)
	}
}
