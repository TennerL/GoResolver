package handlers

import (
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	serverConfigurationActionUpdate          = "update"
	serverConfigurationActionDelete          = "delete"
	serverConfigurationActionIssueCert       = "issue_cert"
	serverConfigurationActionRenewCert       = "renew_cert"
	serverConfigurationActionDeleteCert      = "delete_cert"
	serverConfigurationActionDeleteErrorPage = "delete_error_page"
	serverConfigurationActionDeleteErrorFile = "delete_error_file"
	serverConfigurationActionAddRule         = "add_rule"
	serverConfigurationActionDeleteRule      = "delete_rule"
	serverConfigurationActionCreateVPNFile   = "create-vpn-file"
	serverConfigurationActionUnbanFail2Ban   = "unban_fail2ban"
)

var serverConfigurationPostHandlers = map[string]func(*ServerConfigurationHandler, http.ResponseWriter, *http.Request){
	serverConfigurationActionUpdate:          (*ServerConfigurationHandler).Update,
	serverConfigurationActionDelete:          (*ServerConfigurationHandler).Delete,
	serverConfigurationActionIssueCert:       (*ServerConfigurationHandler).IssueCert,
	serverConfigurationActionRenewCert:       (*ServerConfigurationHandler).RenewCert,
	serverConfigurationActionDeleteCert:      (*ServerConfigurationHandler).DeleteCert,
	serverConfigurationActionDeleteErrorPage: (*ServerConfigurationHandler).DeleteErrorPage,
	serverConfigurationActionDeleteErrorFile: (*ServerConfigurationHandler).DeleteErrorFile,
	serverConfigurationActionAddRule:         (*ServerConfigurationHandler).AddRule,
	serverConfigurationActionDeleteRule:      (*ServerConfigurationHandler).DeleteRule,
	serverConfigurationActionCreateVPNFile:   (*ServerConfigurationHandler).CreateVPNConfig,
	serverConfigurationActionUnbanFail2Ban:   (*ServerConfigurationHandler).UnbanFail2Ban,
}

var serverConfigurationUpdateKeys = []string{
	"top_server_name",
	"system_nginx_config",
	"system_nginx_import",
	"system_site_id[]",
	"system_site_server_name[]",
	"system_site_listen_port[]",
	"system_site_ssl[]",
	"system_site_http2[]",
	"system_site_mode[]",
	"system_site_cert_path[]",
	"system_site_key_path[]",
	"system_site_ssl_config_path[]",
	"system_site_ssl_dhparam_path[]",
	"system_site_root_path[]",
	"system_site_index_files[]",
	"system_site_proxy_pass_url[]",
	"system_site_static_alias_path[]",
	"system_site_php_enabled[]",
	"system_site_php_socket[]",
	"system_site_phpmyadmin_enabled[]",
	"system_site_phpmyadmin_socket[]",
	"system_site_proxy_buffering_off[]",
	"system_site_access_log_off_static[]",
	"system_site_static_expires[]",
	"system_site_static_cache_control[]",
	"vpn_ip",
	"vpn_file",
	"id[]",
	"server_name[]",
	"server_port[]",
	"ssl_enabled[]",
	"ssl_redirect[]",
	"hsts[]",
	"proxy_pass_port[]",
	"proxy_intercept_errors[]",
	"Websockets[]",
	"error_page_id[]",
	"site_id[]",
	"error_file_id[]",
	"enabled[]",
	"error_page_file_id[]",
	"error_code[]",
	"response_type[]",
	"ddos_enabled",
	"ddos_mode",
	"ddos_preset",
	"ddos_rate_limit",
	"ddos_burst",
	"ddos_conn_limit",
	"ddos_syn_rate",
	"ddos_syn_burst",
	"ddos_challenge_delay",
	"ddos_cookie_ttl",
	"ddos_whitelist",
	"fail2ban_enabled",
	"fail2ban_max_retry",
	"fail2ban_find_time",
	"fail2ban_ban_time",
	"fail2ban_status_codes",
	"fail2ban_ignore_ips",
	"fail2ban_use_xff",
	"fail2ban_ban_globally",
}

func canonicalServerConfigurationAction(raw string) string {
	switch normalizeServerConfigurationAction(raw) {
	case serverConfigurationActionUpdate:
		return serverConfigurationActionUpdate
	case serverConfigurationActionDelete:
		return serverConfigurationActionDelete
	case serverConfigurationActionIssueCert, "issuecert":
		return serverConfigurationActionIssueCert
	case serverConfigurationActionRenewCert, "renewcert":
		return serverConfigurationActionRenewCert
	case serverConfigurationActionDeleteCert, "deletecert":
		return serverConfigurationActionDeleteCert
	case serverConfigurationActionDeleteErrorPage, "deleteerrorpage":
		return serverConfigurationActionDeleteErrorPage
	case serverConfigurationActionDeleteErrorFile, "deleteerrorfile":
		return serverConfigurationActionDeleteErrorFile
	case serverConfigurationActionAddRule, "addrule":
		return serverConfigurationActionAddRule
	case serverConfigurationActionDeleteRule, "deleterule":
		return serverConfigurationActionDeleteRule
	case "create_vpn_file", "createvpnfile":
		return serverConfigurationActionCreateVPNFile
	case serverConfigurationActionUnbanFail2Ban, "unbanfail2ban":
		return serverConfigurationActionUnbanFail2Ban
	default:
		return ""
	}
}

func normalizeServerConfigurationAction(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.ReplaceAll(raw, "-", "_")
	raw = strings.ReplaceAll(raw, " ", "_")
	return raw
}

func inferServerConfigurationAction(r *http.Request) string {
	switch {
	case hasFormValue(r.Form, "fail2ban_ip"):
		return serverConfigurationActionUnbanFail2Ban
	case hasFormValue(r.Form, "table") && hasFormValue(r.Form, "chain") && hasFormValue(r.Form, "comment"):
		return serverConfigurationActionDeleteRule
	case hasAnyFormValue(r.Form, "rule_type", "rule_table", "rule_chain", "rule_action", "source_ip", "dest_ip"):
		return serverConfigurationActionAddRule
	case hasFormValue(r.Form, "id") && hasAnyFormValue(r.Form, "Filename", "Path"):
		return serverConfigurationActionDeleteErrorFile
	case hasFormValue(r.Form, "pass") && hasFormValue(r.Form, "vpn_ip"):
		return serverConfigurationActionCreateVPNFile
	}

	switch strings.TrimSpace(r.FormValue("active_tab")) {
	case "tab3":
		if hasFormValue(r.Form, "id") && hasFormValue(r.Form, "serverName") {
			return serverConfigurationActionDelete
		}
	case "tab4":
		if hasFormValue(r.Form, "id") && hasFormValue(r.Form, "serverName") {
			return serverConfigurationActionIssueCert
		}
	case "tab5":
		if hasFormValue(r.Form, "id") {
			if hasAnyFormValue(r.Form, "Filename", "Path") {
				return serverConfigurationActionDeleteErrorFile
			}
			return serverConfigurationActionDeleteErrorPage
		}
	case "tab6":
		if hasFormValue(r.Form, "table") && hasFormValue(r.Form, "chain") && hasFormValue(r.Form, "comment") {
			return serverConfigurationActionDeleteRule
		}
		if hasAnyFormValue(r.Form, "rule_type", "rule_table", "rule_chain", "rule_action", "source_ip", "dest_ip") {
			return serverConfigurationActionAddRule
		}
	case "tab8":
		if hasFormValue(r.Form, "fail2ban_ip") {
			return serverConfigurationActionUnbanFail2Ban
		}
	}

	if looksLikeServerConfigurationUpdate(r.Form) {
		return serverConfigurationActionUpdate
	}

	return ""
}

func resolveServerConfigurationAction(r *http.Request) string {
	if action := canonicalServerConfigurationAction(r.FormValue("action_type")); action != "" {
		return action
	}
	return inferServerConfigurationAction(r)
}

func hasFormValue(values url.Values, key string) bool {
	for _, value := range values[key] {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func hasAnyFormValue(values url.Values, keys ...string) bool {
	for _, key := range keys {
		if hasFormValue(values, key) {
			return true
		}
	}
	return false
}

func hasFormKey(values url.Values, key string) bool {
	_, ok := values[key]
	return ok
}

func looksLikeServerConfigurationUpdate(values url.Values) bool {
	for _, key := range serverConfigurationUpdateKeys {
		if hasFormKey(values, key) {
			return true
		}
	}
	return false
}

func sortedFormKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func parseServerConfigurationForm(r *http.Request) error {
	if r.Form != nil || r.MultipartForm != nil {
		return nil
	}

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		return r.ParseMultipartForm(32 << 20)
	}
	return r.ParseForm()
}

func (h *ServerConfigurationHandler) HandlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := parseServerConfigurationForm(r); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	action := resolveServerConfigurationAction(r)
	logServerConfigurationRequest(r, action)

	handler, ok := serverConfigurationPostHandlers[action]
	if !ok {
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	handler(h, w, r)
}

func logServerConfigurationRequest(r *http.Request, action string) {
	log.Printf("server configuration action=%q raw_action=%q keys=%v", action, r.FormValue("action_type"), sortedFormKeys(r.Form))
	if len(r.Form) == 0 {
		log.Printf(
			"server configuration empty form method=%s content_type=%q content_length=%d referer=%q user_agent=%q",
			r.Method,
			r.Header.Get("Content-Type"),
			r.ContentLength,
			r.Referer(),
			r.UserAgent(),
		)
	}
}
