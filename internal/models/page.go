package models

type PageData struct {
	Active      string
	View        string
	Data        any
	DomainID    string
	ServerID    string
	SuggestedIP string
	Servers     []Server
}

type IPTablesRule struct {
    Table       string
    Chain       string
    Num         string
    Pkts        string
    Bytes       string
    Target      string
    Prot        string
    Opt         string
    In          string
    Out         string
    Source      string
    Destination string
    Extra       string
    Limit       string
}

type IPTablesRuleSpec struct {
    Table        string
    Chain        string
    Action       string
    Position     int
    Protocol     string
    InInterface  string
    OutInterface string
    SourceIP     string
    DestIP       string
    SourcePort   int
    DestPort     int
    ConnLimit    *int
    LimitRate    string
    LimitBurst   string
    SynOnly      bool
    ConnState    string
    IcmpType     string
    ToIP         string
    ToPort       int
    Target       string
    Comment      string
    LogPrefix    string
    LogLevel     string
    RejectWith   string
    ExtraArgs    []string
}

type RuleForm struct {
    RuleType  string
    SourceIP  string
    Port      int
    ConnLimit int
    Rate      string
    Burst     string
    ToIP      string
    ToPort    int
    Target    string
}

type PageDataServerConfig struct {
	Active         string
	View           string
	Data           any
	ServerID       string
	ServerName     string
	IP             string
	VPN_File       string
	ErrorPages     []ServerErrorPages
	ErrorFiles     []ServerErrorFiles
	Sites          []ServerConfiguration
	IPTablesRules  []IPTablesRule
	DDoSPolicy     DDoSPolicy
	Fail2BanPolicy Fail2BanPolicy
	Fail2BanBans   []Fail2BanBan
}
