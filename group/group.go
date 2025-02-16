package group

import (
	"fmt"
	"net"
	"time"

	"magitrickle/models"
	"magitrickle/netfilter-helper"
	"magitrickle/records"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

type Group struct {
	models.Group

	enabled     bool
	nh          *netfilterHelper.NetfilterHelper
	ipset       *netfilterHelper.IPSet
	ipsetToLink *netfilterHelper.IPSetToLink
}

func (g *Group) AddIP(address net.IP, ttl uint32) error {
	return g.ipset.AddIP(address, &ttl)
}

func (g *Group) DelIP(address net.IP) error {
	return g.ipset.DelIP(address)
}

func (g *Group) ListIP() (map[string]*uint32, error) {
	return g.ipset.ListIPs()
}

func (g *Group) Enable() error {
	if g.enabled {
		return nil
	}
	defer func() {
		if !g.enabled {
			_ = g.Disable()
		}
	}()

	if g.FixProtect {
		err := g.nh.IPTables4.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
		if err != nil {
			return fmt.Errorf("failed to fix protect: %w", err)
		}
		err = g.nh.IPTables6.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-j", "_NDM_SL_PROTECT")
		if err != nil {
			return fmt.Errorf("failed to fix protect: %w", err)
		}
	}

	err := g.ipsetToLink.Enable()
	if err != nil {
		return err
	}

	g.enabled = true

	return nil
}

func (g *Group) Disable() []error {
	var errs []error

	if !g.enabled {
		return nil
	}

	if g.FixProtect {
		err := g.nh.IPTables4.Delete("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to remove fix protect: %w", err))
		}
		err = g.nh.IPTables6.Delete("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-j", "_NDM_SL_PROTECT")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to remove fix protect: %w", err))
		}
	}

	err := g.ipsetToLink.Disable()
	if err != nil {
		errs = append(errs, err...)
	}

	g.enabled = false

	return errs
}

func (g *Group) Destroy() []error {
	errs := g.Disable()
	err := g.ipset.Destroy()
	if err != nil {
		errs = append(errs, err)
	}
	return errs
}

func (g *Group) Sync(records *records.Records) error {
	now := time.Now()

	addresses := make(map[string]uint32)
	knownDomains := records.ListKnownDomains()
	for _, domain := range g.Rules {
		if !domain.IsEnabled() {
			continue
		}

		for _, domainName := range knownDomains {
			if !domain.IsMatch(domainName) {
				continue
			}

			domainAddresses := records.GetARecords(domainName)
			for _, address := range domainAddresses {
				ttl := uint32(now.Sub(address.Deadline).Seconds())
				if oldTTL, ok := addresses[string(address.Address)]; !ok || ttl > oldTTL {
					addresses[string(address.Address)] = ttl
				}
			}
		}
	}

	currentAddresses, err := g.ListIP()
	if err != nil {
		return fmt.Errorf("failed to get old ipset list: %w", err)
	}

	for addr, ttl := range addresses {
		if _, exists := currentAddresses[addr]; exists {
			if currentAddresses[addr] == nil {
				continue
			} else {
				if ttl < *currentAddresses[addr] {
					continue
				}
			}
		}
		ip := net.IP(addr)
		err = g.AddIP(ip, ttl)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to add address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("add address")
		}
	}

	for addr := range currentAddresses {
		if _, ok := addresses[addr]; ok {
			continue
		}
		ip := net.IP(addr)
		err = g.DelIP(ip)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to delete address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("del address")
		}
	}

	return nil
}

func (g *Group) NetfilterDHook(iptType, table string) error {
	if g.enabled && g.FixProtect && table == "filter" {
		if iptType == "" || iptType == "iptables" {
			err := g.nh.IPTables4.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
			if err != nil {
				return fmt.Errorf("failed to fix protect: %w", err)
			}
		}
		if iptType == "" || iptType == "ip6tables" {
			err := g.nh.IPTables6.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
			if err != nil {
				return fmt.Errorf("failed to fix protect: %w", err)
			}
		}
	}

	return g.ipsetToLink.NetfilterDHook(iptType, table)
}

func (g *Group) LinkUpdateHook(event netlink.LinkUpdate) error {
	return g.ipsetToLink.LinkUpdateHook(event)
}

func NewGroup(group models.Group, nh *netfilterHelper.NetfilterHelper, ipsetNamePrefix string) (*Group, error) {
	ipsetName := fmt.Sprintf("%s%8x", ipsetNamePrefix, group.ID)
	ipset, err := nh.IPSet(ipsetName)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ipset: %w", err)
	}

	ipsetToLink := nh.IPSetToLink(group.ID.String(), group.Interface, ipsetName)
	return &Group{
		Group:       group,
		nh:          nh,
		ipset:       ipset,
		ipsetToLink: ipsetToLink,
	}, nil
}
