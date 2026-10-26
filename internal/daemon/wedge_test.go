package daemon

import (
	"context"
	"reflect"
	"testing"

	"corpvpn/internal/verbs"
)

func newTestWedgeWatcher(scopedOK bool, fwdOK bool) (*WedgeWatcher, *struct {
	kicks    int
	hostsUps int
	notifies int
	upArgs   [][]verbs.HostsEntry
	messages []string
	upErr    error
}) {
	rec := &struct {
		kicks    int
		hostsUps int
		notifies int
		upArgs   [][]verbs.HostsEntry
		messages []string
		upErr    error
	}{}
	w := &WedgeWatcher{
		TestHost:         "probe.wb-bank.ru",
		ForwarderAddr:    "127.0.0.1",
		ScopedLookup:     func(context.Context, string) bool { return scopedOK },
		ForwarderAnswers: func(context.Context, string) bool { return fwdOK },
		Kick: func() error {
			rec.kicks++
			return nil
		},
		HostsUp: func(entries []verbs.HostsEntry) error {
			rec.hostsUps++
			rec.upArgs = append(rec.upArgs, entries)
			return rec.upErr
		},
		Notify: func(msg string) {
			rec.notifies++
			rec.messages = append(rec.messages, msg)
		},
	}
	return w, rec
}

var wedgeCache = []verbs.HostsEntry{
	{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"},
	{Addr: "10.14.0.82", Name: "sd.wb-bank.ru"},
}

func TestWedgeHealthyCycleDoesNothing(t *testing.T) {
	w, rec := newTestWedgeWatcher(true /* scoped */, true /* fwd */)
	w.Cycle(context.Background(), 1, wedgeCache)
	if rec.kicks != 0 || rec.hostsUps != 0 || rec.notifies != 0 {
		t.Fatalf("healthy cycle must not repair: kicks=%d hostsUps=%d notifies=%d", rec.kicks, rec.hostsUps, rec.notifies)
	}
}

func TestWedgeFirstWedgedCycleKicksOnly(t *testing.T) {
	w, rec := newTestWedgeWatcher(false, true)
	w.Cycle(context.Background(), 1, wedgeCache)
	if rec.kicks != 1 {
		t.Fatalf("kick not run: kicks=%d", rec.kicks)
	}
	if rec.hostsUps != 0 || rec.notifies != 0 {
		t.Fatalf("hosts fallback must wait one interval: hostsUps=%d notifies=%d", rec.hostsUps, rec.notifies)
	}
}

func TestWedgePersistentCycleFallsBackToHostsOnce(t *testing.T) {
	w, rec := newTestWedgeWatcher(false, true)
	w.Cycle(context.Background(), 1, wedgeCache)
	w.Cycle(context.Background(), 2, wedgeCache)
	if rec.hostsUps != 1 {
		t.Fatalf("hosts fallback not installed: hostsUps=%d", rec.hostsUps)
	}
	if len(rec.upArgs) == 1 && !reflect.DeepEqual(rec.upArgs[0], wedgeCache) {
		t.Fatalf("HostsUp must receive the caller cache verbatim, got %+v", rec.upArgs[0])
	}
	if rec.notifies != 1 || rec.messages[0] == "" {
		t.Fatalf("notify expected exactly once with a message: notifies=%d messages=%q", rec.notifies, rec.messages)
	}
	// Third wedged cycle: no duplicate notify, no duplicate install.
	w.Cycle(context.Background(), 3, wedgeCache)
	if rec.hostsUps != 1 || rec.notifies != 1 {
		t.Fatalf("duplicate episode actions: hostsUps=%d notifies=%d", rec.hostsUps, rec.notifies)
	}
}

func TestWedgeRecoveredCycleResetsState(t *testing.T) {
	w, rec := newTestWedgeWatcher(false, true)
	w.Cycle(context.Background(), 1, wedgeCache)
	w.Cycle(context.Background(), 2, wedgeCache) // hosts fallback + notify

	w.ScopedLookup = func(context.Context, string) bool { return true }
	w.Cycle(context.Background(), 3, wedgeCache) // recovery resets the episode

	w.ScopedLookup = func(context.Context, string) bool { return false }
	w.Cycle(context.Background(), 4, wedgeCache) // new episode: kick again
	if rec.kicks != 2 {
		t.Fatalf("state not reset: kicks=%d, want a fresh kick in the new episode", rec.kicks)
	}
	if rec.hostsUps != 1 || rec.notifies != 1 {
		t.Fatalf("new episode must not inherit the old one: hostsUps=%d notifies=%d", rec.hostsUps, rec.notifies)
	}
	w.Cycle(context.Background(), 5, wedgeCache) // wedge survives again
	if rec.hostsUps != 2 || rec.notifies != 2 {
		t.Fatalf("second episode fallback missing: hostsUps=%d notifies=%d", rec.hostsUps, rec.notifies)
	}
}

func TestWedgeHostsUpErrorRecordedNotFatal(t *testing.T) {
	w, rec := newTestWedgeWatcher(false, true)
	rec.upErr = context.DeadlineExceeded
	w.Cycle(context.Background(), 1, wedgeCache)
	w.Cycle(context.Background(), 2, wedgeCache)
	if w.LastErr == nil {
		t.Fatal("HostsUp error must be recorded")
	}
	if rec.notifies != 0 {
		t.Fatalf("notify must not fire on a failed install: notifies=%d", rec.notifies)
	}
	// Not fatal: a later cycle retries the install and can still succeed.
	rec.upErr = nil
	w.Cycle(context.Background(), 3, wedgeCache)
	if rec.hostsUps != 2 || rec.notifies != 1 {
		t.Fatalf("watcher dead after HostsUp error: hostsUps=%d notifies=%d", rec.hostsUps, rec.notifies)
	}
}
