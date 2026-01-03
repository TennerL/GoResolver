package models

type PageData struct {
	Active string
	Data   any
	DomainID string
	ServerID string
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
    Extra       string // COMMENT ONLY
    Limit       string
}



type IPTablesRuleSpec struct {
    Table     string   // filter, nat
    Chain     string   // INPUT, PREROUTING
    Protocol  string   // tcp, udp, all
    SourceIP  string
    DestIP    string
    DestPort  int

    // Modules
    ConnLimit  *int
    LimitRate  string
    LimitBurst string
    SynOnly    bool

    // DNAT
    ToIP       string
    ToPort     int

    Target     string
    Comment    string
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
	Active      string
	Data        any
	ServerID    string
	ServerName  string
	IP          string
	VPN_File    string
	ErrorPages  []ServerErrorPages
	ErrorFiles  []ServerErrorFiles
	Sites       []ServerConfiguration

	IPTablesRules []IPTablesRule 
}

// type PageDataServerConfig struct {
// 	Active string
// 	Data any
// 	ServerID string
// 	ServerName string
// 	IP string 
// 	VPN_File string
// 	ErrorPages []ServerErrorPages
// 	ErrorFiles []ServerErrorFiles
// 	Sites []ServerConfiguration
// }