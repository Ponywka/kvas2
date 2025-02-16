package netfilterHelper

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

type PortRemap struct {
	ChainName string
	Addresses []netlink.Addr
	From      uint16
	To        uint16

	enabled bool
	nh      *NetfilterHelper
}

func (r *PortRemap) insertIPTablesRules(ipt *iptables.IPTables, table string) error {
	if table == "" || table == "nat" {
		preroutingChain := r.nh.ChainPrefix + r.ChainName + "_PRR"
		err := ipt.NewChain("nat", preroutingChain)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		for _, addr := range r.Addresses {
			if !((ipt.Proto() == iptables.ProtocolIPv4 && len(addr.IP) == net.IPv4len) || (ipt.Proto() == iptables.ProtocolIPv6 && len(addr.IP) == net.IPv6len)) {
				continue
			}

			if ipt.Proto() != iptables.ProtocolIPv6 {
				for _, iptablesArgs := range [][]string{
					{"-p", "tcp", "-d", addr.IP.String(), "--dport", fmt.Sprintf("%d", r.From), "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.To)},
					{"-p", "udp", "-d", addr.IP.String(), "--dport", fmt.Sprintf("%d", r.From), "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.To)},
				} {
					err = ipt.AppendUnique("nat", preroutingChain, iptablesArgs...)
					if err != nil {
						return fmt.Errorf("failed to append rule: %w", err)
					}
				}
			} else {
				for _, iptablesArgs := range [][]string{
					{"-p", "tcp", "-d", addr.IP.String(), "--dport", strconv.Itoa(int(r.From)), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", r.To)},
					{"-p", "udp", "-d", addr.IP.String(), "--dport", strconv.Itoa(int(r.From)), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", r.To)},
				} {
					err = ipt.AppendUnique("nat", preroutingChain, iptablesArgs...)
					if err != nil {
						return fmt.Errorf("failed to append rule: %w", err)
					}
				}
			}
		}

		err = ipt.InsertUnique("nat", "PREROUTING", 1, "-j", preroutingChain)
		if err != nil {
			return fmt.Errorf("failed to linking chain: %w", err)
		}
	}

	return nil
}

func (r *PortRemap) deleteIPTablesRules(ipt *iptables.IPTables) []error {
	var errs []error

	preroutingChain := r.nh.ChainPrefix + r.ChainName + "_PRR"
	err := ipt.DeleteIfExists("nat", "PREROUTING", "-j", preroutingChain)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = ipt.ClearAndDeleteChain("nat", preroutingChain)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	return errs
}

func (r *PortRemap) enable() error {
	err := r.insertIPTablesRules(r.nh.IPTables4, "")
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables6, "")
	if err != nil {
		return err
	}

	r.enabled = true
	return nil
}

func (r *PortRemap) Enable() error {
	if r.enabled {
		return nil
	}

	err := r.nh.IPTables4.ClearChain("nat", r.ChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = r.enable()
	if err != nil {
		r.Disable()
		return err
	}

	err = r.nh.IPTables6.ClearChain("nat", r.ChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = r.enable()
	if err != nil {
		r.Disable()
		return err
	}

	return nil
}

func (r *PortRemap) Disable() []error {
	var errs []error
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4)...)
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6)...)
	r.enabled = false
	return errs
}

func (r *PortRemap) NetfilterDHook(iptType, table string) error {
	if !r.enabled {
		return nil
	}
	if iptType == "" || iptType == "iptables" {
		err := r.insertIPTablesRules(r.nh.IPTables4, table)
		if err != nil {
			return err
		}
	}
	if iptType == "" || iptType == "ip6tables" {
		err := r.insertIPTablesRules(r.nh.IPTables6, table)
		if err != nil {
			return err
		}
	}
	return nil
}

func (nh *NetfilterHelper) PortRemap(name string, from, to uint16, addr []netlink.Addr) *PortRemap {
	return &PortRemap{
		nh:        nh,
		ChainName: name,
		Addresses: addr,
		From:      from,
		To:        to,
	}
}
