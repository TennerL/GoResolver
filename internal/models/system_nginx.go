package models

type SystemNginxSite struct {
	ID                 string `json:"id"`
	ServerName         string `json:"server_name"`
	ListenPort         int    `json:"listen_port"`
	SSL                bool   `json:"ssl"`
	HTTP2              bool   `json:"http2"`
	CertPath           string `json:"cert_path"`
	KeyPath            string `json:"key_path"`
	SSLConfigPath      string `json:"ssl_config_path"`
	SSLDhParamPath     string `json:"ssl_dhparam_path"`
	Mode               string `json:"mode"`
	EnableDDoS         bool   `json:"enable_ddos"`
	RootPath           string `json:"root_path"`
	IndexFiles         string `json:"index_files"`
	ProxyPassURL       string `json:"proxy_pass_url"`
	StaticAliasPath    string `json:"static_alias_path"`
	PHPEnabled         bool   `json:"php_enabled"`
	PHPSocket          string `json:"php_socket"`
	PHPMyAdminEnabled  bool   `json:"phpmyadmin_enabled"`
	PHPMyAdminSocket   string `json:"phpmyadmin_socket"`
	ProxyBufferingOff  bool   `json:"proxy_buffering_off"`
	AccessLogOffStatic bool   `json:"access_log_off_static"`
	StaticExpires      string `json:"static_expires"`
	StaticCacheControl string `json:"static_cache_control"`
}
