package app_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

var movedMX = zoneFile("moved_mx")

func TestRerunAddsAStepAndShowsWhatChanged(t *testing.T) {
	resolver, setZone := mutableDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	first := h.waitSteps(c.ID, 1)[0]
	if first.ComparedTo != 0 || first.Changes != nil {
		t.Fatalf("first run should not be compared: %+v", first)
	}

	setZone(movedMX) // the customer moved their mail
	if code := h.rerun(c.ID, "dns_lookup", "example.com"); code != http.StatusOK {
		t.Fatalf("rerun: %d", code)
	}
	steps := h.waitSteps(c.ID, 2)

	if steps[0].ID != first.ID || steps[0].Changes != nil {
		t.Fatalf("earlier step changed: %+v", steps[0])
	}
	second := steps[1]
	if second.ComparedTo != first.ID {
		t.Fatalf("compared_to = %d, want %d", second.ComparedTo, first.ID)
	}
	got := map[string]change{}
	for _, ch := range second.Changes {
		got[ch.Field] = ch
	}
	mx := got["records.MX"]
	if !slices.Equal(mx.Removed, []string{"10 mail.example.com."}) || !slices.Equal(mx.Added, []string{"10 mx1.newhost.net.", "20 mx2.newhost.net."}) {
		t.Errorf("MX change = %+v", mx)
	}
	if soa := got["records.SOA"]; len(soa.Removed) != 1 || !strings.Contains(soa.Added[0], " 2025 ") {
		t.Errorf("SOA change = %+v", soa)
	}
	if len(got) != 2 {
		t.Errorf("only MX and SOA changed, got %+v", second.Changes)
	}

	// An identical third run is compared to the second and reports no changes.
	h.rerun(c.ID, "dns_lookup", "example.com")
	third := h.waitSteps(c.ID, 3)[2]
	if third.ComparedTo != second.ID || len(third.Changes) != 0 {
		t.Fatalf("third = %+v", third)
	}
}

func TestReorderedAnswersAreNotAChange(t *testing.T) {
	resolver, setZone := mutableDNS(t, `
example.com. 300 IN NS a.example.net.
example.com. 300 IN NS b.example.net.`, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	setZone(`
example.com. 300 IN NS b.example.net.
example.com. 300 IN NS a.example.net.`)
	h.rerun(c.ID, "dns_lookup", "example.com")
	if second := h.waitSteps(c.ID, 2)[1]; len(second.Changes) != 0 {
		t.Fatalf("reordering reported as change: %+v", second.Changes)
	}
}

func TestFailedRunsAreSkippedWhenComparing(t *testing.T) {
	resolver, setZone := mutableDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}, CheckTimeout: 300 * time.Millisecond})
	c := newCase(h, "example.com")
	first := h.waitSteps(c.ID, 1)[0]

	setZone(noAnswer) // the resolver goes quiet: this run fails
	h.rerun(c.ID, "dns_lookup", "example.com")
	h.waitSteps(c.ID, 2)
	setZone(exampleZone)
	h.rerun(c.ID, "dns_lookup", "example.com")
	steps := h.waitSteps(c.ID, 3)
	if steps[1].Status != "failed" || steps[2].ComparedTo != first.ID {
		t.Fatalf("steps = %+v", steps)
	}
}

func TestRerunRejectsChecksThatDoNotApply(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": "203.0.113.7"}, nil)
	for _, tc := range []struct{ check, target string }{
		{"dns_lookup", "203.0.113.7"}, // not for IPs
		{"dns_lookup", "other.com"},   // not a Target of this Case
		{"no_such_check", "example.com"},
	} {
		if code := h.rerun(c.ID, tc.check, tc.target); code != http.StatusBadRequest {
			t.Errorf("%s on %s: %d, want 400", tc.check, tc.target, code)
		}
	}
	if code := h.rerun(999, "dns_lookup", "example.com"); code != http.StatusNotFound {
		t.Errorf("unknown case: %d", code)
	}
}

func TestFinishEventCarriesTheChanges(t *testing.T) {
	resolver, setZone := mutableDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	resp, err := http.Get(h.web.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	setZone(movedMX)
	h.rerun(c.ID, "dns_lookup", "example.com")

	got := make(chan diffedStep, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var ev struct{ Step diffedStep }
			json.Unmarshal([]byte(data), &ev)
			if ev.Step.Status == "ok" {
				got <- ev.Step
				return
			}
		}
	}()
	select {
	case s := <-got:
		if s.ComparedTo == 0 || len(s.Changes) == 0 {
			t.Fatalf("event step = %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no finish event")
	}
}
