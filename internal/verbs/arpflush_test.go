package verbs

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const netstatMixed = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#24            UCSIg             bridge100      !
10.24.67.4/32      192.168.64.5       UGSc                bridge100
10.15.0.82         link#24            UHLWIg             bridge100      !
10.15.0.83         192.168.64.5       UGSc                bridge100
192.168.1.1        58:d3:12:b0:b8:be  UHLWIir                en0   1192
192.168.1.1/32     link#14            UCS                    en0      !
`

func TestArpFlushFindClonedRoutes(t *testing.T) {
	t.Run("empty output", func(t *testing.T) {
		got := FindClonedRoutes("", "bridge100")
		if len(got) != 0 {
			t.Fatalf("want no routes, got %v", got)
		}
	})

	t.Run("mixed table finds only the stale clone", func(t *testing.T) {
		got := FindClonedRoutes(netstatMixed, "bridge100")
		want := []ClonedRoute{{Addr: "10.15.0.82", Iface: "bridge100"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("empty iface matches any", func(t *testing.T) {
		got := FindClonedRoutes(netstatMixed, "")
		want := []ClonedRoute{{Addr: "10.15.0.82", Iface: "bridge100"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("iface filter excludes foreign clones", func(t *testing.T) {
		out := netstatMixed + "10.15.0.90       link#14            UHLWIi                 en0      !\n"
		got := FindClonedRoutes(out, "bridge100")
		want := []ClonedRoute{{Addr: "10.15.0.82", Iface: "bridge100"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		got = FindClonedRoutes(out, "en0")
		want = []ClonedRoute{{Addr: "10.15.0.90", Iface: "en0"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("LLINFO in the flags field matches without the bang marker", func(t *testing.T) {
		out := "10.15.0.82       link#24            UHLWI,LLINFO        bridge100\n"
		got := FindClonedRoutes(out, "bridge100")
		want := []ClonedRoute{{Addr: "10.15.0.82", Iface: "bridge100"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("non-cloned gatewayless line without UHLWI or bang is skipped", func(t *testing.T) {
		out := "10.15.0.82       link#24            UCS                bridge100\n"
		got := FindClonedRoutes(out, "bridge100")
		if len(got) != 0 {
			t.Fatalf("want no routes, got %v", got)
		}
	})
}

func TestArpFlushFlushClonedRoutes(t *testing.T) {
	type call struct {
		name string
		args []string
	}

	netstatOut := "Internet:\n" +
		"10.15.0.82       link#24            UHLWIg             bridge100      !\n" +
		"10.15.0.83       link#24            UHLWIg             bridge100      !\n"

	t.Run("runs netstat then delete and arp per clone in order", func(t *testing.T) {
		var calls []call
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls = append(calls, call{name: name, args: args})
			if name == "netstat" {
				return netstatOut, nil
			}
			return "", nil
		}
		if err := FlushClonedRoutes("bridge100", run); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []call{
			{name: "netstat", args: []string{"-rn", "-f", "inet"}},
			{name: "route", args: []string{"-n", "delete", "-host", "10.15.0.82"}},
			{name: "arp", args: []string{"-d", "10.15.0.82"}},
			{name: "route", args: []string{"-n", "delete", "-host", "10.15.0.83"}},
			{name: "arp", args: []string{"-d", "10.15.0.83"}},
		}
		if len(calls) != len(want) {
			t.Fatalf("got %d calls, want %d: %v", len(calls), len(want), calls)
		}
		for i, w := range want {
			if calls[i].name != w.name || !reflect.DeepEqual(calls[i].args, w.args) {
				t.Fatalf("call %d = %v, want %v", i, calls[i], w)
			}
		}
	})

	t.Run("continues after a failed entry and returns the first error", func(t *testing.T) {
		var calls []string
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "route" && strings.Contains(strings.Join(args, " "), "10.15.0.82") {
				return "route: not in table", errors.New("exit status 1")
			}
			if name == "netstat" {
				return netstatOut, nil
			}
			return "", nil
		}
		err := FlushClonedRoutes("bridge100", run)
		if err == nil {
			t.Fatal("want the first entry error, got nil")
		}
		wantTail := []string{
			"arp -d 10.15.0.82",
			"route -n delete -host 10.15.0.83",
			"arp -d 10.15.0.83",
		}
		gotTail := calls[len(calls)-len(wantTail):]
		if !reflect.DeepEqual(gotTail, wantTail) {
			t.Fatalf("tail after failure = %v, want %v", gotTail, wantTail)
		}
	})

	t.Run("netstat failure stops the flush", func(t *testing.T) {
		calls := 0
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls++
			return "", errors.New("boom")
		}
		if err := FlushClonedRoutes("bridge100", run); err == nil {
			t.Fatal("want netstat error, got nil")
		}
		if calls != 1 {
			t.Fatalf("want a single call, got %d", calls)
		}
	})
}
