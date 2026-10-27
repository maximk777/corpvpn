package hostops

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeExec records every call as one "name args..." line and serves canned
// results per exact command line.
type fakeExec struct {
	calls   []string
	results map[string]fakeResult
	// sequence serves one result per call in order for a repeated command
	// (e.g. the route get before an add and the verify get after it), then
	// falls back to results.
	sequence map[string][]fakeResult
}

type fakeResult struct {
	stdout string
	err    error
}

func (f *fakeExec) exec(_ context.Context, name string, args ...string) (string, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if seq := f.sequence[line]; len(seq) > 0 {
		f.sequence[line] = seq[1:]
		return seq[0].stdout, seq[0].err
	}
	if r, ok := f.results[line]; ok {
		return r.stdout, r.err
	}
	return "", nil
}

func (f *fakeExec) did(line string) bool { return slices.Contains(f.calls, line) }

func (f *fakeExec) indexOf(line string) int { return slices.Index(f.calls, line) }

// Route fixtures: noRoute errors like `route -n get` on an unroutable
// address; viaOurs / viaForeign / gatewaylessClone mimic real outputs.
var noRoute = fakeResult{err: errors.New("route: writing to routing socket: not in table")}

func viaOurs(addr string) fakeResult {
	return fakeResult{stdout: "   route to: " + addr + "\ndestination: " + addr +
		"\n    gateway: 192.168.64.2\n  interface: bridge100\n"}
}

func viaForeign(addr string) fakeResult {
	return fakeResult{stdout: "   route to: " + addr + "\ndestination: " + addr +
		"\n    gateway: 192.168.1.1\n  interface: en0\n"}
}

func gatewaylessClone(addr string) fakeResult {
	return fakeResult{stdout: "   route to: " + addr + "\ndestination: " + addr +
		"\n  interface: bridge100\n"}
}

// viaDefaultRoute mimics macOS `route -n get <ip>` when NO specific route
// exists: it answers with the DEFAULT route entry (destination: default,
// gateway = the LAN router). That is an address simply not routed yet --
// not a foreign VPN client owning it.
func viaDefaultRoute(addr string) fakeResult {
	return fakeResult{stdout: "   route to: " + addr + "\ndestination: default" +
		"\n    gateway: 192.168.176.1\n  interface: en0\n"}
}

// bankConfig is a resolver-mode config whose subnets are bank addresses
// (/32 host prefixes), the only shape S5 hands over since the rework.
func bankConfig(dir string) Config {
	return Config{
		StateDir: dir,
		Subnets: []netip.Prefix{
			netip.MustParsePrefix("10.52.0.7/32"),
			netip.MustParsePrefix("10.60.0.9/32"),
		},
		CorpDomains:  []string{"wb-bank.ru"},
		OVPNDomains:  []string{"stage-openvpn"},
		CorpDNS:      []string{"10.0.0.53", "10.0.0.54"},
		BankDomain:   "wb-bank.ru",
		DNSMode:      "resolver",
		IfaceGateway: "192.168.64.2",
	}
}

// newResolverDir points the package-level /etc/resolver stand-in at a fresh
// temp dir so tests never touch the real system.
func newResolverDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "resolver")
	old := resolverDir
	resolverDir = dir
	t.Cleanup(func() { resolverDir = old })
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(b) != want {
		t.Fatalf("%s = %q, want %q", path, b, want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s must not exist", path)
	}
}

func TestApplyNetAddsMissingRoutesAndRecordsThem(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		// No route at all -> add; the verify get after the add sees ours.
		"route -n get 10.52.0.7": {noRoute, viaOurs("10.52.0.7")},
		"route -n get 10.60.0.9": {noRoute, viaOurs("10.60.0.9")},
	}
	rep, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	if len(rep.Contested) != 0 {
		t.Fatalf("contested = %v, want empty", rep.Contested)
	}
	wantCalls := []string{
		"route -n get 10.52.0.7",
		"route -n add -net 10.52.0.7/32 192.168.64.2",
		"route -n get 10.52.0.7",
		"route -n get 10.60.0.9",
		"route -n add -net 10.60.0.9/32 192.168.64.2",
		"route -n get 10.60.0.9",
	}
	if !slices.Equal(rec.calls, wantCalls) {
		t.Fatalf("exec calls = %v, want %v", rec.calls, wantCalls)
	}
	// Only actually-installed prefixes are recorded, so down removes
	// exactly what was applied.
	assertFile(t, filepath.Join(dir, "routes"), "10.52.0.7/32\n10.60.0.9/32\n")
	// Exactly ONE scoped resolver file -- the bank domain, recorded alone
	// for down. The forwarder refuses names outside it, so scoping the
	// legacy corp list (wb.ru) here would black-hole those names; the ovpn
	// domain is a validated passthrough, never a resolver file.
	assertFile(t, filepath.Join(dir, "resolver"), "wb-bank.ru\n")
	assertFile(t, filepath.Join(resolverDir, "wb-bank.ru"), "nameserver 127.0.0.1\n")
	assertAbsent(t, filepath.Join(resolverDir, "stage-openvpn"))
}

func TestApplyNetHealthyExistingRouteIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1]
	var rec fakeExec
	rec.results = map[string]fakeResult{
		"route -n get 10.52.0.7": viaOurs("10.52.0.7"),
	}
	rep, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	if len(rep.Contested) != 0 {
		t.Fatalf("contested = %v, want empty", rep.Contested)
	}
	if !slices.Equal(rec.calls, []string{"route -n get 10.52.0.7"}) {
		t.Fatalf("exec calls = %v, want only the route get", rec.calls)
	}
	// Nothing was installed, so nothing is recorded for down to remove.
	assertFile(t, filepath.Join(dir, "routes"), "")
}

func TestApplyNetReplacesClonedRoute(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1]
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		// First get hits the cloned gatewayless route; after the delete
		// and re-add the verify get must see our gateway.
		"route -n get 10.52.0.7": {gatewaylessClone("10.52.0.7"), viaOurs("10.52.0.7")},
	}
	rep, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNetReport: %v (a gatewayless clone must be healed)", err)
	}
	if len(rep.Contested) != 0 {
		t.Fatalf("contested = %v, want empty", rep.Contested)
	}
	wantCalls := []string{
		"route -n get 10.52.0.7",
		"route -n delete -host 10.52.0.7",
		"route -n add -net 10.52.0.7/32 192.168.64.2",
		"route -n get 10.52.0.7",
	}
	if !slices.Equal(rec.calls, wantCalls) {
		t.Fatalf("exec calls = %v, want %v", rec.calls, wantCalls)
	}
	assertFile(t, filepath.Join(dir, "routes"), "10.52.0.7/32\n")
}

func TestApplyNetForeignGatewayIsContested(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1]
	var rec fakeExec
	rec.results = map[string]fakeResult{
		"route -n get 10.52.0.7": viaForeign("10.52.0.7"),
	}
	rep, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNetReport: %v (a foreign gateway must be skipped, not fought)", err)
	}
	if !slices.Equal(rep.Contested, []string{"10.52.0.7"}) {
		t.Fatalf("contested = %v, want [10.52.0.7]", rep.Contested)
	}
	if !slices.Equal(rec.calls, []string{"route -n get 10.52.0.7"}) {
		t.Fatalf("exec calls = %v, want only the route get (no add, no delete)", rec.calls)
	}
	assertFile(t, filepath.Join(dir, "routes"), "")
	// DNS is unaffected by a contested route.
	assertFile(t, filepath.Join(rdir, "wb-bank.ru"), "nameserver 127.0.0.1\n")
	assertAbsent(t, filepath.Join(rdir, "stage-openvpn"))
}

// The default-route fallback must install the /32: destination "default"
// means nothing specific routes the address yet (live: btg.wb-bank.ru
// blackholed because the fallback looked like a foreign contest).
func TestApplyNetDefaultRouteFallbackInstallsRoute(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1]
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		"route -n get 10.52.0.7": {viaDefaultRoute("10.52.0.7"), viaOurs("10.52.0.7")},
	}
	rep, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	if len(rep.Contested) != 0 {
		t.Fatalf("contested = %v, want empty (the default-route fallback is not a contest)", rep.Contested)
	}
	wantCalls := []string{
		"route -n get 10.52.0.7",
		"route -n add -net 10.52.0.7/32 192.168.64.2",
		"route -n get 10.52.0.7",
	}
	if !slices.Equal(rec.calls, wantCalls) {
		t.Fatalf("exec calls = %v, want %v", rec.calls, wantCalls)
	}
	assertFile(t, filepath.Join(dir, "routes"), "10.52.0.7/32\n")
}

func TestApplyNetVerifyAfterAddFailsOnWrongGateway(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1]
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		// The add claims success but the route table still points elsewhere:
		// the per-prefix verify must fail and keep the prefix unrecorded.
		"route -n get 10.52.0.7": {noRoute, viaForeign("10.52.0.7")},
	}
	_, err := ApplyNetReport(context.Background(), cfg, rec.exec)
	if err == nil || !strings.Contains(err.Error(), "10.52.0.7") {
		t.Fatalf("ApplyNetReport = %v, want a per-prefix verify failure", err)
	}
	assertFile(t, filepath.Join(dir, "routes"), "")
}

func TestApplyNetWritesResolverFileRegardlessOfLegacyMode(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.DNSMode = "primary" // legacy value from the root-net-up caller; ignored
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		"route -n get 10.52.0.7": {noRoute, viaOurs("10.52.0.7")},
		"route -n get 10.60.0.9": {noRoute, viaOurs("10.60.0.9")},
	}
	if _, err := ApplyNetReport(context.Background(), cfg, rec.exec); err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	for _, c := range rec.calls {
		if strings.Contains(c, "networksetup") {
			t.Fatalf("primary-mode DNS must be gone, got %q", c)
		}
	}
	assertFile(t, filepath.Join(rdir, "wb-bank.ru"), "nameserver 127.0.0.1\n")
}

func TestApplyNetSkipsResolverWithoutBankDomain(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.BankDomain = "" // no bank domain known: no scoped file to write
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		"route -n get 10.52.0.7": {noRoute, viaOurs("10.52.0.7")},
		"route -n get 10.60.0.9": {noRoute, viaOurs("10.60.0.9")},
	}
	if _, err := ApplyNetReport(context.Background(), cfg, rec.exec); err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	assertAbsent(t, filepath.Join(dir, "resolver"))
	entries, err := os.ReadDir(rdir) // never created: the gate skips before MkdirAll
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("resolver dir entries = %v, want empty", entries)
	}
	if !rec.did("route -n add -net 10.52.0.7/32 192.168.64.2") {
		t.Fatalf("routes must still be applied, got %v", rec.calls)
	}
}

func TestApplyNetInvalidConfigRejectedBeforeExec(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"bad corp domain", func(c *Config) { c.CorpDomains = []string{"bad_domain"} }},
		{"bad ovpn domain", func(c *Config) { c.OVPNDomains = []string{"a..b"} }},
		{"bad bank domain", func(c *Config) { c.BankDomain = "bad_domain" }},
		{"ipv6 prefix", func(c *Config) {
			c.Subnets = append(c.Subnets, netip.MustParsePrefix("2001:db8::/32"))
		}},
		{"bad gateway", func(c *Config) { c.IfaceGateway = "nope" }},
		{"dns newline injection", func(c *Config) { c.CorpDNS = []string{"10.0.0.53\nnameserver evil"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := bankConfig(dir)
			tc.mut(&cfg)
			var rec fakeExec
			if _, err := ApplyNetReport(context.Background(), cfg, rec.exec); err == nil {
				t.Fatal("ApplyNetReport must fail on invalid config")
			}
			if len(rec.calls) != 0 {
				t.Fatalf("exec calls = %v, want zero", rec.calls)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("state dir must stay untouched, got %v", entries)
			}
		})
	}
}

// ApplyNet must keep its plain-error signature: the root-net-up dispatch in
// main.go discards the report.
func TestApplyNetSignatureStillReturnsBareError(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	cfg := bankConfig(dir)
	var rec fakeExec
	rec.sequence = map[string][]fakeResult{
		"route -n get 10.52.0.7": {noRoute, viaOurs("10.52.0.7")},
		"route -n get 10.60.0.9": {noRoute, viaOurs("10.60.0.9")},
	}
	var err error = ApplyNet(context.Background(), cfg, rec.exec)
	if err != nil {
		t.Fatalf("ApplyNet: %v", err)
	}
}

func TestRemoveNetUndoesRecordedState(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	writeFile(t, filepath.Join(dir, "routes"), "10.52.0.7/32\n10.60.0.9/32\n")
	writeFile(t, filepath.Join(dir, "resolver"), "wb-bank.ru\n")
	writeFile(t, filepath.Join(dir, "dns-primary"), "Wi-Fi\n8.8.8.8 1.0.0.1\n")
	writeFile(t, filepath.Join(rdir, "wb-bank.ru"), "nameserver 127.0.0.1\n")

	var rec fakeExec
	if err := RemoveNet(context.Background(), dir, rec.exec); err != nil {
		t.Fatalf("RemoveNet: %v", err)
	}
	wantCalls := []string{
		"route -n delete -net 10.52.0.7/32",
		"route -n delete -net 10.60.0.9/32",
		"networksetup -setdnsservers Wi-Fi 8.8.8.8 1.0.0.1",
	}
	if !slices.Equal(rec.calls, wantCalls) {
		t.Fatalf("exec calls = %v, want %v", rec.calls, wantCalls)
	}
	assertAbsent(t, filepath.Join(dir, "routes"))
	assertAbsent(t, filepath.Join(dir, "resolver"))
	assertAbsent(t, filepath.Join(dir, "dns-primary"))
	assertAbsent(t, filepath.Join(rdir, "wb-bank.ru"))
}

// Up and down must agree on the resolver state: the single bank-domain file
// applyResolverDNS records is exactly what RemoveNet removes.
func TestApplyThenRemoveResolverRoundtrip(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	cfg := bankConfig(dir)
	cfg.Subnets = cfg.Subnets[:1] // route already healthy: no route mutations
	var rec fakeExec
	rec.results = map[string]fakeResult{
		"route -n get 10.52.0.7": viaOurs("10.52.0.7"),
	}
	if _, err := ApplyNetReport(context.Background(), cfg, rec.exec); err != nil {
		t.Fatalf("ApplyNetReport: %v", err)
	}
	assertFile(t, filepath.Join(rdir, "wb-bank.ru"), "nameserver 127.0.0.1\n")
	if err := RemoveNet(context.Background(), dir, rec.exec); err != nil {
		t.Fatalf("RemoveNet: %v", err)
	}
	assertAbsent(t, filepath.Join(rdir, "wb-bank.ru"))
	assertAbsent(t, filepath.Join(dir, "resolver"))
}

func TestRemoveNetEmptyOriginalsSetsEmpty(t *testing.T) {
	dir := t.TempDir()
	newResolverDir(t)
	writeFile(t, filepath.Join(dir, "dns-primary"), "Wi-Fi\n")
	var rec fakeExec
	if err := RemoveNet(context.Background(), dir, rec.exec); err != nil {
		t.Fatalf("RemoveNet: %v", err)
	}
	want := []string{"networksetup -setdnsservers Wi-Fi Empty"}
	if !slices.Equal(rec.calls, want) {
		t.Fatalf("exec calls = %v, want %v", rec.calls, want)
	}
	assertAbsent(t, filepath.Join(dir, "dns-primary"))
}

func TestRemoveNetTamperedStateStillCleansAndReports(t *testing.T) {
	dir := t.TempDir()
	rdir := newResolverDir(t)
	writeFile(t, filepath.Join(dir, "routes"), "10.52.0.7/32\nnot-a-prefix\n")
	writeFile(t, filepath.Join(dir, "resolver"), "wb-bank.ru\nbad_domain\n")
	writeFile(t, filepath.Join(dir, "dns-primary"), "Wi-Fi\n8.8.8.8\n")
	writeFile(t, filepath.Join(rdir, "wb-bank.ru"), "nameserver 127.0.0.1\n")

	var rec fakeExec
	err := RemoveNet(context.Background(), dir, rec.exec)
	if err == nil {
		t.Fatal("RemoveNet must report tampered state lines")
	}
	for _, frag := range []string{"not-a-prefix", "bad_domain"} {
		if !strings.Contains(err.Error(), frag) {
			t.Fatalf("error %q must mention %q", err, frag)
		}
	}
	wantCalls := []string{
		"route -n delete -net 10.52.0.7/32",
		"networksetup -setdnsservers Wi-Fi 8.8.8.8",
	}
	if !slices.Equal(rec.calls, wantCalls) {
		t.Fatalf("exec calls = %v, want %v (valid lines still cleaned)", rec.calls, wantCalls)
	}
	assertAbsent(t, filepath.Join(dir, "routes"))
	assertAbsent(t, filepath.Join(dir, "resolver"))
	assertAbsent(t, filepath.Join(rdir, "wb-bank.ru"))
}

func TestRemoveNetWithoutStateIsNoop(t *testing.T) {
	var rec fakeExec
	if err := RemoveNet(context.Background(), t.TempDir(), rec.exec); err != nil {
		t.Fatalf("RemoveNet: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("exec calls = %v, want zero", rec.calls)
	}
}

func TestExecHostRejectsNonWhitelistedBinary(t *testing.T) {
	var rec fakeExec
	if _, err := execHost(context.Background(), rec.exec, "sh", "-c", "echo pwned"); err == nil {
		t.Fatal("sh must be rejected")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("exec calls = %v, want zero (runner never reached)", rec.calls)
	}
}
