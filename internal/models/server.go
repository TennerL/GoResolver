package models

type Server struct {
	ID        int
	Domain_ID int
	Name      string
	IP        string
	VPN_File  string
	Status    string
	Uptime    string
	IsSystem  bool
}
