package models

type PageData struct {
	Active string
	Data   any
	DomainID string
	ServerID string
}

type PageDataServerConfig struct {
	Active string
	Data any
	ServerID string
	ServerName string
	IP string 
	VPN_File string
	ErrorPages []ServerErrorPages
	ErrorFiles []ServerErrorFiles
	Sites []ServerConfiguration
}