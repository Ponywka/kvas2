package netfilterHelper

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type IPSet struct {
	SetName string
}

func (r *IPSet) AddIP(addr net.IP, timeout *uint32) error {
	var err error
	if len(addr) == net.IPv4len {
		err = netlink.IpsetAdd(r.SetName+"_4", &netlink.IPSetEntry{
			IP:      addr,
			Timeout: timeout,
			Replace: true,
		})
	} else if len(addr) == net.IPv6len {
		err = netlink.IpsetAdd(r.SetName+"_6", &netlink.IPSetEntry{
			IP:      addr,
			Timeout: timeout,
			Replace: true,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}
	return nil
}

func (r *IPSet) DelIP(addr net.IP) error {
	var err error
	if len(addr) == net.IPv4len {
		err = netlink.IpsetDel(r.SetName+"_4", &netlink.IPSetEntry{
			IP: addr,
		})
	} else if len(addr) == net.IPv6len {
		err = netlink.IpsetDel(r.SetName+"_6", &netlink.IPSetEntry{
			IP: addr,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to delete address: %w", err)
	}
	return nil
}

func (r *IPSet) ListIPs() (map[string]*uint32, error) {
	addresses := make(map[string]*uint32)
	list, err := netlink.IpsetList(r.SetName + "_4")
	if err != nil {
		return nil, err
	}
	for _, entry := range list.Entries {
		addresses[string(entry.IP)] = entry.Timeout
	}
	list, err = netlink.IpsetList(r.SetName + "_6")
	if err != nil {
		return nil, err
	}
	for _, entry := range list.Entries {
		addresses[string(entry.IP)] = entry.Timeout
	}
	return addresses, nil
}

func (r *IPSet) Destroy() error {
	err := netlink.IpsetDestroy(r.SetName + "_4")
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	err = netlink.IpsetDestroy(r.SetName + "_6")
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	return nil
}

func (nh *NetfilterHelper) IPSet(name string) (*IPSet, error) {
	ipset := &IPSet{
		SetName: name,
	}
	err := ipset.Destroy()
	if err != nil {
		return nil, err
	}

	err = netlink.IpsetCreate(ipset.SetName+"_4", "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(300),
		Family:  unix.AF_INET,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset: %w", err)
	}

	err = netlink.IpsetCreate(ipset.SetName+"_6", "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(300),
		Family:  unix.AF_INET6,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset: %w", err)
	}

	return ipset, nil
}
