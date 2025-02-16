package netfilterHelper

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
)

type NetfilterHelper struct {
	ChainPrefix string
	IPTables4   *iptables.IPTables
	IPTables6   *iptables.IPTables
}

func New(chainPrefix string) (*NetfilterHelper, error) {
	ipt4, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return nil, fmt.Errorf("iptables init fail: %w", err)
	}

	ipt6, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
	if err != nil {
		return nil, fmt.Errorf("ip6tables init fail: %w", err)
	}

	return &NetfilterHelper{
		ChainPrefix: chainPrefix,
		IPTables4:   ipt4,
		IPTables6:   ipt6,
	}, nil
}
