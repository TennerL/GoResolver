package models

type ServerConfiguration struct {
	ID                     int
	Server_Name            string
	Site_Enabled           int
	Server_Port            int
	SSL_Enabled            int
	SSL_Redirect           int
	HSTS                   int
	Proxy_Pass_Port        int
	Proxy_Intercept_Errors int
	Proxy_Connect_Timeout  int
	Proxy_Read_Timeout     int
	Proxy_Send_Timeout     int
	Websockets             int
	IP                     string
	VPN_File               []byte
	Port                   int
	ServerID               string
	Name                   string
	Cert_Path              string
	Key_Path               string
	Cert_Issued            string
	Cert_Expiration        string
	Cert_Renew_Scheduled   string
	LetsEncryptConfigFile  string
}

type ServerErrorPages struct {
	ID           string
	Server_ID    string
	Site_ID      string
	Server_Name  string
	ErrorPage_ID string

	Name       string
	Enabled    bool
	Is_Default bool
}

type ServerErrorFiles struct {
	ID string

	Error_Code   string
	ResponseType string
	Filename     string
	File         []byte
	Path         string
}

type DDoSPolicy struct {
	ServerID       string
	Enabled        bool
	Mode           string
	Preset         string
	RateLimit      int
	Burst          int
	ConnLimit      int
	SynRate        int
	SynBurst       int
	ChallengeDelay int
	CookieTTL      int
	Whitelist      string
}

type Fail2BanPolicy struct {
	ServerID         string
	Enabled          bool
	MaxRetry         int
	FindTimeSeconds  int
	BanTimeSeconds   int
	StatusCodes      string
	IgnoreIPs        string
	UseXForwardedFor bool
	BanGlobally      bool
}

type Fail2BanBan struct {
	ServerID  string
	IP        string
	HitCount  int
	BannedAt  string
	ExpiresAt string
}
