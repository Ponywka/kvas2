package netfilterHelper

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

func (nh *NetfilterHelper) cleanIPTables(ipt *iptables.IPTables) error {
	jumpToChainPrefix := fmt.Sprintf("-j %s", nh.ChainPrefix)
	for _, table := range []string{"nat", "mangle"} {
		chainListToDelete := make([]string, 0)

		chains, err := ipt.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing chains error: %w", err)
		}

		for _, chain := range chains {
			if strings.HasPrefix(chain, nh.ChainPrefix) {
				chainListToDelete = append(chainListToDelete, chain)
				continue
			}

			rules, err := ipt.List(table, chain)
			if err != nil {
				return fmt.Errorf("listing rules error: %w", err)
			}

			for _, rule := range rules {
				if !strings.Contains(rule, jumpToChainPrefix) {
					continue
				}

				ruleSlice := strings.Split(rule, " ")
				if len(ruleSlice) < 2 || ruleSlice[0] != "-A" || ruleSlice[1] != chain {
					continue
				}

				err = ipt.Delete(table, chain, ruleSlice[2:]...)
				if err != nil {
					return fmt.Errorf("rule deletion error: %w", err)
				}
			}
		}

		for _, chain := range chainListToDelete {
			err = ipt.ClearAndDeleteChain(table, chain)
			if err != nil {
				return fmt.Errorf("deleting chain error: %w", err)
			}
		}
	}

	return nil
}

func (nh *NetfilterHelper) CleanIPTables() error {
	err := nh.cleanIPTables(nh.IPTables4)
	if err != nil {
		return err
	}
	err = nh.cleanIPTables(nh.IPTables6)
	if err != nil {
		return err
	}
	return nil
}
