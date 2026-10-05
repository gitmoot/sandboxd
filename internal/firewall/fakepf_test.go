package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const testMainNAT = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"

// fakePF is pfctl, route and sysctl on a fake Mac. Loads go through
// pfctlLoad, which models pfctl independently of render.
type fakePF struct {
	enabled    bool
	mainNAT    string
	// anchors are other anchors under com.apple and their pfctl -sn output,
	// such as Internet Sharing's NAT.
	anchors map[string]string
	skipped    map[string]bool
	filter     string // pfctl -a <anchor> -sr
	nat        string // pfctl -a <anchor> -sn
	tables     map[string][]netip.Prefix
	flushes    map[string]int
	loadedText []string // policy files handed to pfctl -f
	route      string   // default route interface; "" for none
	forwarding bool
	// forwardingWrites counts sysctl -w calls.
	forwardingWrites int
}

func newFakePF() *fakePF {
	return &fakePF{enabled: true, mainNAT: testMainNAT, skipped: map[string]bool{},
		tables: map[string][]netip.Prefix{}, flushes: map[string]int{}, route: "en0"}
}

func (f *fakePF) attach(s *Server) *fakePF {
	s.pf = f.pf
	s.run = f.run
	return f
}

// setLoaded puts pfctl readback into the anchor as if some other helper
// version had loaded it, without tables.
func (f *fakePF) setLoaded(filter, nat string) {
	f.filter, f.nat, f.tables = filter, nat, map[string][]netip.Prefix{}
}

func (f *fakePF) run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name + " " + strings.Join(args, " ") {
	case "/sbin/route -n get default":
		if f.route == "" {
			return nil, errors.New("route: writing to routing socket: not in table")
		}
		return []byte("   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: " +
			f.route + "\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"), nil
	case "/usr/sbin/sysctl -n net.inet.ip.forwarding":
		if f.forwarding {
			return []byte("1\n"), nil
		}
		return []byte("0\n"), nil
	case "/usr/sbin/sysctl -w net.inet.ip.forwarding=1":
		f.forwardingWrites++
		f.forwarding = true
		return []byte("net.inet.ip.forwarding: 0 -> 1\n"), nil
	case "/usr/sbin/sysctl -w net.inet.ip.forwarding=0":
		f.forwardingWrites++
		f.forwarding = false
		return []byte("net.inet.ip.forwarding: 1 -> 0\n"), nil
	}
	return nil, fmt.Errorf("unexpected command %s %v", name, args)
}

func (f *fakePF) pf(_ context.Context, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	switch {
	case command == "-s info":
		if f.enabled {
			return []byte("Status: Enabled for 0 days 01:02:03\n"), nil
		}
		return []byte("Status: Disabled\n"), nil
	case command == "-sr":
		return []byte(testMainRules), nil
	case command == "-sn":
		return []byte(f.mainNAT), nil
	case strings.HasPrefix(command, "-s Interfaces -v -i "):
		name := args[4]
		if f.skipped[name] {
			return []byte(name + " (skip)\n"), nil
		}
		return []byte(name + "\n"), nil
	case command == "-a "+anchor+" -sr":
		return []byte(f.filter), nil
	case command == "-a "+anchor+" -sn":
		return []byte(f.nat), nil
	case command == "-a com.apple -v -s Anchors":
		out := "  " + anchor + "\n"
		for name := range f.anchors {
			out += "  " + name + "\n"
		}
		return []byte(out), nil
	case len(args) == 3 && args[0] == "-a" && args[2] == "-sn" && (args[1] == "com.apple" || f.anchors[args[1]] != ""):
		return []byte(f.anchors[args[1]]), nil
	case command == "-a "+anchor+" -F rules":
		f.filter = ""
		return nil, nil
	case command == "-a "+anchor+" -F nat":
		f.nat = ""
		return nil, nil
	case command == "-a "+anchor+" -F Tables":
		f.tables = map[string][]netip.Prefix{}
		return nil, nil
	case strings.HasPrefix(command, "-F states -i "):
		f.flushes[args[3]]++
		return nil, nil
	case len(args) >= 6 && args[0] == "-a" && args[1] == anchor && args[2] == "-t" && args[4] == "-T":
		table, ok := f.tables[args[3]]
		if !ok {
			return nil, errors.New("pfctl: Table does not exist.")
		}
		switch {
		case args[5] == "show" && len(args) == 6:
			var out strings.Builder
			for _, prefix := range table {
				out.WriteString("   " + prefixText(prefix) + "\n")
			}
			return []byte(out.String()), nil
		case args[5] == "replace":
			replaced, err := parseItems(args[6:])
			if err != nil {
				return nil, err
			}
			f.tables[args[3]] = replaced
			return nil, nil
		}
	case len(args) >= 4 && args[0] == "-a" && args[1] == anchor && (args[len(args)-2] == "-nf" || args[len(args)-2] == "-f"):
		input, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		filter, nat, tables, err := pfctlLoad(string(input), !(len(args) == 6 && args[2] == "-o" && args[3] == "none"))
		if err != nil {
			return nil, err
		}
		if args[len(args)-2] == "-f" {
			f.loadedText = append(f.loadedText, string(input))
			f.filter, f.nat, f.tables = filter, nat, tables
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected PF command %v", args)
}

func parseItems(items []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		parsed, ok := parseTable(item)
		if !ok || len(parsed) != 1 {
			return nil, fmt.Errorf("pfctl: bad table entry %q", item)
		}
		prefixes = append(prefixes, parsed[0])
	}
	return prefixes, nil
}

// pfctlLoad is what pfctl prints back for a loaded anchor file: the filter
// rules (`-sr`) and NAT rules (`-sn`) in pfctl's normalized form, in load
// order, and the tables it defines. Without `-o none`, pfctl's default basic
// optimizer groups the rules by address family (all inet, then all inet6),
// measured with `pfctl -o basic -nvf` on the Mac Studio 2026-09-30; that
// broke the 3-slot arm there. The normalization follows pfctl's
// print_rule: "block" prints its default "drop"; "from any to any" prints
// "all"; a port prints with "="; a pass rule prints its default state and
// TCP flags; a NAT to an interface's addresses is a round-robin pool.
func pfctlLoad(policy string, optimized bool) (filter, nat string, tables map[string][]netip.Prefix, err error) {
	var out, inet6, natOut []string
	tables = map[string][]netip.Prefix{}
	for _, line := range strings.Split(strings.TrimSpace(policy), "\n") {
		if rest, ok := strings.CutPrefix(line, "table <"); ok {
			name, rest, _ := strings.Cut(rest, ">")
			var items []string
			if _, list, found := strings.Cut(rest, "{ "); found {
				items = strings.Split(strings.TrimSuffix(list, " }"), ", ")
			}
			if tables[name], err = parseItems(items); err != nil {
				return "", "", nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "nat on ") {
			if strings.Contains(line, "-> (") {
				line += " round-robin"
			}
			natOut = append(natOut, line)
			continue
		}
		line = strings.Replace(line, "block in quick", "block drop in quick", 1)
		line = strings.Replace(line, " from any to any", " all", 1)
		if strings.HasPrefix(line, "pass in quick") {
			// pfctl clears the default TCP flags on non-TCP rules.
			line = strings.ReplaceAll(line, " port ", " port = ")
			if strings.Contains(line, " proto udp ") {
				line += " keep state"
			} else {
				line += " flags S/SA keep state"
			}
		}
		if optimized && strings.HasSuffix(line, " inet6 all") {
			inet6 = append(inet6, line)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(append(out, inet6...), "\n"), strings.Join(natOut, "\n"), tables, nil
}
