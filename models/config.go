package models

type Config struct {
	ConfigVersion string  `yaml:"configVersion"`
	App           App     `yaml:"app"`
	Groups        []Group `yaml:"groups"`
}

type App struct {
	DNSProxy  DNSProxy  `yaml:"dnsProxy"`
	Netfilter Netfilter `yaml:"netfilter"`
	Link      []string  `yaml:"link"`
	LogLevel  string    `yaml:"logLevel"`
}

type DNSProxy struct {
	Host           DNSProxyServer `yaml:"host"`
	Upstream       DNSProxyServer `yaml:"upstream"`
	DisableRemap53 bool           `yaml:"disableRemap53"`
	DisableFakePTR bool           `yaml:"disableFakePTR"`
}

type DNSProxyServer struct {
	Address string `yaml:"address"`
	Port    uint16 `yaml:"port"`
}

type Netfilter struct {
	IPTables IPTables `yaml:"iptables"`
	IPSet    IPSet    `yaml:"ipset"`
}

type IPTables struct {
	ChainPrefix string `yaml:"chainPrefix"`
}

type IPSet struct {
	TablePrefix   string `yaml:"tablePrefix"`
	AdditionalTTL uint32 `yaml:"additionalTTL"`
}
