package app_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// Shared seam-1 test harness: a fake DNS server, the server under test, and
// HTTP helpers. Check tests bring their own fakes in their own files.

// fakeDNS serves zone (lines in zone-file presentation format) on 127.0.0.1.
// Queries for anything not in zone get NXDOMAIN; queries for a refused type get REFUSED.
// With silent=true it never answers.
func fakeDNS(t *testing.T, zone string, silent bool, refuse ...uint16) string {
	addr, _ := mutableDNS(t, zone, silent, refuse...)
	return addr
}

// noAnswer, passed to mutableDNS's setter, makes the server stop answering.
const noAnswer = "<no answer>"

// mutableDNS is fakeDNS plus a function that replaces the zone it serves.
func mutableDNS(t *testing.T, zone string, silent bool, refuse ...uint16) (string, func(zone string)) {
	t.Helper()
	parse := func(zone string) []dns.RR {
		var rrs []dns.RR
		for _, line := range strings.Split(strings.TrimSpace(zone), "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			rr, err := dns.NewRR(line)
			if err != nil {
				t.Fatalf("bad zone line %q: %v", line, err)
			}
			rrs = append(rrs, rr)
		}
		return rrs
	}
	var current atomic.Pointer[[]dns.RR]
	var mute atomic.Bool
	initial := parse(zone)
	current.Store(&initial)
	// UDP and TCP on the same port, like a real resolver (TCP serves
	// truncated-answer retries). Another test may already hold that TCP port,
	// so pick a fresh pair until both are free.
	var pc net.PacketConn
	var ln net.Listener
	for range 50 {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
		pc = nil
	}
	if pc == nil {
		t.Fatal("no free UDP+TCP port pair for the fake DNS server")
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if silent || mute.Load() {
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if slices.Contains(refuse, q.Qtype) {
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
			return
		}
		known := false
		for _, rr := range *current.Load() {
			if strings.EqualFold(rr.Header().Name, q.Name) {
				known = true
				if rr.Header().Rrtype == q.Qtype {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if !known {
			m.Rcode = dns.RcodeNameError
		}
		if w.LocalAddr().Network() == "udp" {
			size := dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
			m.Truncate(size)
		}
		w.WriteMsg(m)
	})
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: ln, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return pc.LocalAddr().String(), func(zone string) {
		mute.Store(zone == noAnswer)
		if zone == noAnswer {
			return
		}
		rrs := parse(zone)
		current.Store(&rrs)
	}
}

type harness struct {
	t   *testing.T
	srv *app.Server
	web *httptest.Server
}

func start(t *testing.T, cfg app.Config) *harness {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	srv, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, web: httptest.NewServer(srv.Handler())}
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.web.Close()
	h.srv.Close()
}

func (h *harness) do(method, path string, body any, out any) int {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, h.web.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			h.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

type step struct {
	ID     int64  `json:"id"`
	Check  string `json:"check"`
	Target string `json:"target"`
	Status string `json:"status"`
	Error  string `json:"error"`
	Result struct {
		Rcode   string              `json:"rcode"`
		Records map[string][]string `json:"records"`
		Errors  map[string]string   `json:"errors"`
	} `json:"result"`
}

type caseView struct {
	ID      int64        `json:"id"`
	Targets []targetView `json:"targets"`
	Steps   []step       `json:"steps"`
}

// waitStep polls the Case until its first Step leaves "running".
func (h *harness) waitStep(caseID int64) step {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var c caseView
		h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
		if len(c.Steps) > 0 && c.Steps[0].Status != "running" {
			return c.Steps[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("step never finished")
	return step{}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// Zones live in testdata/zones, shared with the Rust tests.
func zoneFile(name string) string {
	b, err := os.ReadFile("../../testdata/zones/" + name + ".zone")
	if err != nil {
		panic(err)
	}
	return string(b)
}

var exampleZone = zoneFile("example")

type change struct {
	Field   string   `json:"field"`
	Removed []string `json:"removed"`
	Added   []string `json:"added"`
}

type diffedStep struct {
	ID         int64    `json:"id"`
	Status     string   `json:"status"`
	ComparedTo int64    `json:"compared_to"`
	Changes    []change `json:"changes"`
}

type diffedCase struct {
	Steps []diffedStep `json:"steps"`
}

func (h *harness) rerun(caseID int64, check, target string) int {
	h.t.Helper()
	return h.do("POST", "/api/cases/"+itoa(caseID)+"/steps", map[string]string{"check": check, "target": target}, nil)
}

// waitSteps polls until the Case has n Steps, none running.
func (h *harness) waitSteps(caseID int64, n int) []diffedStep {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var c diffedCase
		h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
		if len(c.Steps) == n && !slices.ContainsFunc(c.Steps, func(s diffedStep) bool { return s.Status == "running" }) {
			return c.Steps
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("case never had %d finished steps", n)
	return nil
}

// findingWith returns the first Finding with code, or nil.
func findingWith(fs []finding, code string) *finding {
	if i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == code }); i != -1 {
		return &fs[i]
	}
	return nil
}

// severityOf returns the severity of the first Finding with code, or "".
func severityOf(fs []finding, code string) string {
	if f := findingWith(fs, code); f != nil {
		return f.Severity
	}
	return ""
}
