package models

type PageData struct {
	Active string
	Data   any
	DomainID string
	ServerID string
}

type IPTablesRule struct {
	Num        string
	Pkts       string
	Bytes      string
	Target     string
	Prot       string
	Opt        string
	In         string
	Out        string
	Source     string
	Destination string
	Extra      string 
	Limit 		string
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