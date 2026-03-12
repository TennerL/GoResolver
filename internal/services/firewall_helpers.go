package services

import (
	"GoResolver/internal/models"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	firewallFamilyIPv4 = "ipv4"
	firewallFamilyIPv6 = "ipv6"
)

func normalizeFirewallFamily(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "4", "ip4", "ipv4":
		return firewallFamilyIPv4
	case "6", "ip6", "ipv6":
		return firewallFamilyIPv6
	default:
		return ""
	}
}

func firewallBinaryForFamily(family string) string {
	if family == firewallFamilyIPv6 {
		return "/sbin/ip6tables"
	}
	return "/sbin/iptables"
}

func firewallBinaryAvailable(family string) bool {
	_, err := os.Stat(firewallBinaryForFamily(family))
	return err == nil
}

func firewallFamilyForValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "/") {
		_, netw, err := net.ParseCIDR(raw)
		if err != nil || netw == nil {
			return ""
		}
		if netw.IP.To4() != nil {
			return firewallFamilyIPv4
		}
		return firewallFamilyIPv6
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return firewallFamilyIPv4
	}
	return firewallFamilyIPv6
}

func inferFirewallFamily(spec models.IPTablesRuleSpec) (string, error) {
	family := normalizeFirewallFamily(spec.Family)
	for _, candidate := range []string{spec.SourceIP, spec.DestIP, spec.ToIP} {
		if candidateFamily := firewallFamilyForValue(candidate); candidateFamily != "" {
			if family == "" {
				family = candidateFamily
				continue
			}
			if family != candidateFamily {
				return "", fmt.Errorf("mixed firewall families in rule")
			}
		}
	}
	if family == "" {
		family = firewallFamilyIPv4
	}
	return family, nil
}

func buildFirewallRuleArgs(spec models.IPTablesRuleSpec, family string) []string {
	args := []string{}

	if spec.Table != "" && spec.Table != "filter" {
		args = append(args, "-t", spec.Table)
	}

	action := "-A"
	if strings.EqualFold(spec.Action, "insert") {
		action = "-I"
	}
	args = append(args, action, spec.Chain)
	if action == "-I" && spec.Position > 0 {
		args = append(args, fmt.Sprintf("%d", spec.Position))
	}

	if spec.Protocol != "" && spec.Protocol != "all" {
		args = append(args, "-p", spec.Protocol)
	}

	if spec.InInterface != "" {
		args = append(args, "-i", spec.InInterface)
	}

	if spec.OutInterface != "" {
		args = append(args, "-o", spec.OutInterface)
	}

	if spec.SynOnly {
		args = append(args, "--syn")
	}

	if spec.SourceIP != "" {
		args = append(args, "-s", spec.SourceIP)
	}

	if spec.DestIP != "" {
		args = append(args, "-d", spec.DestIP)
	}

	if spec.SourcePort > 0 {
		args = append(args, "--sport", fmt.Sprintf("%d", spec.SourcePort))
	}

	if spec.DestPort > 0 {
		args = append(args, "--dport", fmt.Sprintf("%d", spec.DestPort))
	}

	if spec.ConnLimit != nil {
		mask := "32"
		if family == firewallFamilyIPv6 {
			mask = "128"
		}
		args = append(args,
			"-m", "connlimit",
			"--connlimit-above", fmt.Sprintf("%d", *spec.ConnLimit),
			"--connlimit-mask", mask,
		)
	}

	if spec.LimitRate != "" {
		args = append(args,
			"-m", "limit",
			"--limit", spec.LimitRate,
		)
		if spec.LimitBurst != "" {
			args = append(args, "--limit-burst", spec.LimitBurst)
		}
	}

	if spec.ConnState != "" {
		args = append(args, "-m", "conntrack", "--ctstate", spec.ConnState)
	}

	if spec.IcmpType != "" {
		args = append(args, "--icmp-type", spec.IcmpType)
	}

	hasJump := hasJumpArg(spec.ExtraArgs)
	if len(spec.ExtraArgs) > 0 {
		args = append(args, spec.ExtraArgs...)
	}

	if !hasJump && spec.Target == "DNAT" {
		args = append(args,
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", spec.ToIP, spec.ToPort),
		)
	} else if !hasJump && spec.Target != "" {
		args = append(args, "-j", spec.Target)

		if spec.Target == "LOG" && spec.LogPrefix != "" {
			args = append(args, "--log-prefix", spec.LogPrefix)
		}
		if spec.Target == "LOG" && spec.LogLevel != "" {
			args = append(args, "--log-level", spec.LogLevel)
		}
		if spec.Target == "REJECT" && spec.RejectWith != "" {
			args = append(args, "--reject-with", spec.RejectWith)
		}
	}

	if spec.Comment != "" {
		args = append(args, "-m", "comment", "--comment", spec.Comment)
	}

	return args
}

func runFirewallCommand(family string, args []string) ([]byte, error) {
	cmd := exec.Command("sudo", append([]string{firewallBinaryForFamily(family)}, args...)...)
	return cmd.CombinedOutput()
}

func localFirewallFamilies() []string {
	families := map[string]struct{}{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addrIP(addr)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				families[firewallFamilyIPv4] = struct{}{}
				continue
			}
			if ip.To16() != nil {
				families[firewallFamilyIPv6] = struct{}{}
			}
		}
	}
	return orderedFirewallFamilies(families)
}

func addrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

func orderedFirewallFamilies(families map[string]struct{}) []string {
	ordered := make([]string, 0, len(families))
	for _, family := range []string{firewallFamilyIPv4, firewallFamilyIPv6} {
		if _, ok := families[family]; ok {
			ordered = append(ordered, family)
		}
	}
	return ordered
}

func filterIPsByFirewallFamily(entries []string, family string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if firewallFamilyForValue(entry) == family {
			out = append(out, entry)
		}
	}
	return out
}

func firewallDestinationForFamily(destIP, family string) string {
	if firewallFamilyForValue(destIP) == family {
		return strings.TrimSpace(destIP)
	}
	return ""
}

func firewallFamiliesForServer(destIP string, entries []string) ([]string, error) {
	families := map[string]struct{}{}
	for _, family := range localFirewallFamilies() {
		if firewallBinaryAvailable(family) {
			families[family] = struct{}{}
		}
	}

	explicit := map[string]struct{}{}
	if family := firewallFamilyForValue(destIP); family != "" {
		explicit[family] = struct{}{}
	}
	for _, entry := range entries {
		if family := firewallFamilyForValue(entry); family != "" {
			explicit[family] = struct{}{}
		}
	}
	for family := range explicit {
		if !firewallBinaryAvailable(family) {
			return nil, fmt.Errorf("%s is not available", firewallBinaryForFamily(family))
		}
		families[family] = struct{}{}
	}

	if len(families) == 0 {
		for _, family := range []string{firewallFamilyIPv4, firewallFamilyIPv6} {
			if firewallBinaryAvailable(family) {
				families[family] = struct{}{}
				break
			}
		}
	}

	return orderedFirewallFamilies(families), nil
}

func firewallHashSuffix(family string) string {
	if family == firewallFamilyIPv6 {
		return "v6"
	}
	return "v4"
}
