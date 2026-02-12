package handlers

import (
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"net/url"
	"io"
	"time"
	"fmt"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func valueAt(values []string, idx int) string {
	if idx >= 0 && idx < len(values) {
		return values[idx]
	}
	return ""
}

func maxLen(slices ...[]string) int {
	max := 0
	for _, s := range slices {
		if len(s) > max {
			max = len(s)
		}
	}
	return max
}

type ServerConfigurationHandler struct {
	Tmpl    *template.Template
	Service *services.ServerConfigurationService
}

func NewServerConfigurationHandler() *ServerConfigurationHandler {
	funcMap := mergeFuncMaps(baseFuncMap(), template.FuncMap{
		"extractPort":  extractPort,
		"extractLimit": extractLimit,
		"contains":     contains,
	})

	tmpl := template.Must(template.New("layout.html").
		Funcs(funcMap).
		ParseFiles(
			"web/templates/layout.html",
			"web/templates/serverconfiguration.html",
		),
	)

	return &ServerConfigurationHandler{
		Service: services.NewServerConfigurationService(),
		Tmpl:    tmpl,
	}
}

func (h *ServerConfigurationHandler) HandlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action_type")

	log.Println(action)

	switch action {
	case "update":
		h.Update(w, r)
	case "delete":
		h.Delete(w, r)
	case "issue_cert":
		h.IssueCert(w, r)
	case "renew_cert":
		h.RenewCert(w, r)
	case "delete_cert":
		h.DeleteCert(w, r)
	case "delete_error_page":
		h.DeleteErrorPage(w, r)
	case "delete_error_file":
		h.DeleteErrorFile(w, r)
	case "add_rule":
		h.AddRule(w, r)
	case "delete_rule":
		h.DeleteRule(w, r)
	case "create-vpn-file":
		h.CreateVPNConfig(w, r)
	case "unban_fail2ban":
		h.UnbanFail2Ban(w, r)
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}

func (h *ServerConfigurationHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	
	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}

	conf := h.Service.GetServerConfiguration(serverID)
	policy, _ := h.Service.GetDDoSPolicy(serverID)
	fail2banPolicy, _ := h.Service.GetFail2BanPolicy(serverID)
	fail2banBans := h.Service.ListFail2BanBans(serverID)
	if len(conf) == 0 {
		srv, err := h.Service.GetServerBasics(serverID)
		if err != nil {
			http.Error(w, "No server config found", http.StatusNotFound)
			return
		}

		page := models.PageDataServerConfig{
			Active:     "servers",
			Data:       []models.ServerConfiguration{},
			ServerID:   serverID,
			ServerName: srv.Name,
			IP:         srv.IP,
			VPN_File:   srv.VPN_File,
			ErrorPages: h.Service.GetServerErrorPages(serverID),
			ErrorFiles: h.Service.GetServerErrorFiles(),
			DDoSPolicy: policy,
			Fail2BanPolicy: fail2banPolicy,
			Fail2BanBans:   fail2banBans,
		}

		if srv.IP != "" {
			rules, err := h.Service.ListIPTablesRules()
			if err != nil {
				log.Println("iptables error:", err)
			} else {
				page.IPTablesRules = FilterRulesForServer(rules, serverID, srv.IP)
			}
		}

		if err := h.Tmpl.ExecuteTemplate(w, "layout", page); err != nil {
			log.Println("template execute error:", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
		return
	}
	
	errorPages := h.Service.GetServerErrorPages(serverID)
	errorFiles := h.Service.GetServerErrorFiles()

	vpnText := string(conf[0].VPN_File)


	page := models.PageDataServerConfig{
		Active:     "servers",
		Data:       conf,
		ServerID:   serverID,
		ServerName: conf[0].Name,
		IP:         conf[0].IP,
		VPN_File:   vpnText, 
		ErrorPages: errorPages,
		ErrorFiles: errorFiles,
		DDoSPolicy: policy,
		Fail2BanPolicy: fail2banPolicy,
		Fail2BanBans:   fail2banBans,
	}
	rules, err := h.Service.ListIPTablesRules()
	rulesForServer := FilterRulesForServer(rules, serverID, conf[0].IP)
	if err != nil {
		log.Println("iptables error:", err)
	} else {
		page.IPTablesRules = rulesForServer
	}


	if err := h.Tmpl.ExecuteTemplate(w, "layout", page); err != nil {
		log.Println("template execute error:", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}



func (h *ServerConfigurationHandler) Update(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	tab := r.FormValue("active_tab")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	ids := r.Form["id[]"]
	topServerName := r.FormValue("top_server_name")
	vpnIP := strings.TrimSpace(r.FormValue("vpn_ip"))
	vpnText := r.FormValue("vpn_file")
	vpnBytes := []byte(vpnText)

	serverNames := r.Form["server_name[]"]
	serverPorts := r.Form["server_port[]"]
	sslEnabled := r.Form["ssl_enabled[]"]
	sslRedirect := r.Form["ssl_redirect[]"]
	proxyPassPorts := r.Form["proxy_pass_port[]"]
	proxyErrors := r.Form["proxy_intercept_errors[]"]
	websocketsEnabled := r.Form["Websockets[]"]

	n := maxLen(ids, serverNames, serverPorts, sslEnabled, sslRedirect, proxyPassPorts, proxyErrors, websocketsEnabled)
	for i := 0; i < n; i++ {
		idStr := valueAt(ids, i)
		serverName := strings.TrimSpace(valueAt(serverNames, i))
		if idStr == "" && serverName == "" {
			continue
		}

		id, _ := strconv.Atoi(idStr)
		serverPort, _ := strconv.Atoi(valueAt(serverPorts, i))
		ssl, _ := strconv.Atoi(valueAt(sslEnabled, i))
		ssl_redirect, _ := strconv.Atoi(valueAt(sslRedirect, i))
		proxyPort, _ := strconv.Atoi(valueAt(proxyPassPorts, i))
		proxyErr, _ := strconv.Atoi(valueAt(proxyErrors, i))
		websockets, _ := strconv.Atoi(valueAt(websocketsEnabled, i))

		if idStr == "" {
			// INSERT new server config
			err := h.Service.InsertServerConfiguration(models.ServerConfiguration{
				ServerID:               serverID,
				Server_Name:            serverName,
				Server_Port:            serverPort,
				SSL_Enabled:            ssl,
				SSL_Redirect:           ssl_redirect,
				Proxy_Pass_Port:        proxyPort,
				Proxy_Intercept_Errors: proxyErr,
				Websockets:             websockets,
			})
			if err != nil {
				log.Println("Insert failed:", err)
				http.Error(w, "Insert failed", http.StatusInternalServerError)
				return
			}
		} else {
			// UPDATE existing server config
			err := h.Service.UpdateServerConfiguration(models.ServerConfiguration{
				ID:                     id,
				Name:                   topServerName,
				IP:                     vpnIP,
				ServerID:               serverID,
				Server_Name:            serverName,
				Server_Port:            serverPort,
				SSL_Enabled:            ssl,
				SSL_Redirect:           ssl_redirect,
				Proxy_Pass_Port:        proxyPort,
				Proxy_Intercept_Errors: proxyErr,
				VPN_File:               vpnBytes,
				Websockets:             websockets,
			})
			if err != nil {
				log.Println("Update failed:", err)
				http.Error(w, "Update failed", http.StatusInternalServerError)
				return
			}
		}
		log.Printf("Saved SC id=%d name=%s\n", id, serverNames[i])
	}

	// --- ERROR PAGES UPDATE/INSERT ---
	efIDs := r.Form["error_file_id[]"]
	epIDs := r.Form["error_page_id[]"]
	epSiteIDs := r.Form["site_id[]"]
	epEnabledArr := r.Form["enabled[]"]

	nErrPages := maxLen(epIDs, efIDs, epSiteIDs, epEnabledArr)

	for i := 0; i < nErrPages; i++ {
		id := ""
		if i < len(epIDs) {
			id = epIDs[i]
		}

		siteID := ""
		if i < len(epSiteIDs) {
			siteID = epSiteIDs[i]
		}

		errorFileID := ""
		if i < len(efIDs) {
			errorFileID = efIDs[i]
		}

		enabled := false
		if i < len(epEnabledArr) {
			enabled = epEnabledArr[i] == "1"
		}
		if errorFileID == "" {
			continue
		}

		ep := models.ServerErrorPages{
			ID:           id,
			Server_ID:    serverID,
			Site_ID:      siteID,
			ErrorPage_ID: errorFileID,
			Enabled:      enabled,
		}

		if ep.ID == "" {
			h.Service.InsertErrorPage(ep)
		} else {
			h.Service.SaveErrorPage(ep)
		}
	}

	efID := r.Form["error_page_file_id[]"]
	efErrorCodes := r.Form["error_code[]"]
	efResponseTypes := r.Form["response_type[]"]

	nErrFiles := maxLen(efID, efErrorCodes, efResponseTypes)
	for i := 0; i < nErrFiles; i++ {
		id := valueAt(efID, i)
		if id == "" {
			continue
		}

		errorCode := strings.TrimSpace(valueAt(efErrorCodes, i))
		responseType := strings.TrimSpace(valueAt(efResponseTypes, i))
		if errorCode == "" || responseType == "" {
			continue
		}

		err := h.Service.UpdateErrorFiles(models.ServerErrorFiles{
			ID:           id,
			Error_Code:   errorCode,
			ResponseType: responseType,
		})

		if err != nil {
			log.Println("Update error files failed:", err)
			http.Error(w, "Update failed", http.StatusInternalServerError)
			return
		}
	}

	if err := h.applyDDoSFromForm(r, serverID); err != nil {
		http.Error(w, "Failed to apply DDoS policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.applyFail2BanFromForm(r, serverID); err != nil {
		http.Error(w, "Failed to apply Fail2Ban policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if vpnIP != "" {
		clientName := fmt.Sprintf("client-%s", serverID)
		if err := h.Service.AssignStaticVPNIP(clientName, vpnIP); err != nil {
			log.Println("Update VPN IP failed:", err)
			http.Error(w, "Update VPN IP failed", http.StatusInternalServerError)
			return
		}
	}

	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) UploadErrorPage(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Invalid upload", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File missing", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	settings := services.NewSettingsService()
	path := settings.GetValue("paths.error_pages")

	ef := models.ServerErrorFiles{
		Error_Code:  r.FormValue("error_code"),
		ResponseType: r.FormValue("response_type"),
		Filename:    header.Filename,
		File:        data,
		Path: 		 path,
	}

	h.Service.UploadErrorPage(ef)
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func (h *ServerConfigurationHandler) GetErrorFile(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	content, err := h.Service.GetErrorFile(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func (h *ServerConfigurationHandler) UpdateErrorFile(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read failed", http.StatusBadRequest)
		return
	}

	if err := h.Service.UpdateErrorFile(id, data); err != nil {
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ServerConfigurationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.FormValue("id")
	serverName := r.FormValue("serverName")

	err := h.Service.Delete(id, serverName)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tab := r.FormValue("active_tab")
	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) DeleteErrorFile(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]

	id := r.FormValue("id")

	ef := models.ServerErrorFiles{
		ID:			 id,
		Filename:    r.FormValue("Filename"),
		Path:		 r.FormValue("Path"),
	}

	err := h.Service.DeleteErrorFile(ef)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	tab := r.FormValue("active_tab")
	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) IssueCert(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusBadRequest)
		return 
	}
	serverName := r.FormValue("serverName")
	id := r.FormValue("id")

	err := h.Service.IssueCert(id, serverName)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tab := r.FormValue("active_tab")
	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) RenewCert(w http.ResponseWriter, r *http.Request){
	serverID := mux.Vars(r)["id"]

	id := r.FormValue("id")

	err := h.Service.RenewCert(id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tab := r.FormValue("active_tab")
	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) DeleteCert(w http.ResponseWriter, r *http.Request){
	serverID := mux.Vars(r)["id"]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusBadRequest)
		return 
	}
	id := r.FormValue("id")

	err := h.Service.DeleteCert(id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tab := r.FormValue("active_tab")
	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) DeleteErrorPage(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Missing error_page_id", http.StatusBadRequest)
		return
	}

	if err := h.Service.DeleteErrorPage(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirectWithTab(w, r, serverID, "tab5")
}

func FilterRulesForServer(rules []models.IPTablesRule, serverID string, serverIPs ...string) []models.IPTablesRule {
    var filtered []models.IPTablesRule

    ipSet := make(map[string]bool)
    for _, ip := range serverIPs {
        ipSet[ip] = true
    }

    for _, r := range rules {
        if ipSet[r.Source] || ipSet[r.Destination] || isServerRule(r.Extra, serverID) || isGeneralGoResolverRule(r.Extra) {
            filtered = append(filtered, r)
        }
    }

    return filtered
}

func isServerRule(comment, serverID string) bool {
	if comment == "" || serverID == "" {
		return false
	}
	prefixes := []string{
		"GoResolver:Fail2Ban:" + serverID + ":",
		"GoResolver:DDoS:" + serverID + ":",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(comment, p) {
			return true
		}
	}
	return false
}

func isGeneralGoResolverRule(comment string) bool {
	if comment == "" {
		return false
	}
	if !strings.HasPrefix(comment, "GoResolver:") {
		return false
	}
	if strings.Contains(comment, ":DDoS:") {
		return false
	}
	if strings.Contains(comment, ":Fail2Ban:") {
		return false
	}
	if strings.Contains(comment, ":MASQUERADE") {
		return false
	}
	return true
}


func (h *ServerConfigurationHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	ruleType := r.FormValue("rule_type")

	port, _ := strconv.Atoi(r.FormValue("port"))
	sourcePort, _ := strconv.Atoi(r.FormValue("source_port"))
	toPort, _ := strconv.Atoi(r.FormValue("to_port"))
	position, _ := strconv.Atoi(r.FormValue("rule_position"))

	spec := models.IPTablesRuleSpec{
		Table:       r.FormValue("rule_table"),
		Chain:       r.FormValue("rule_chain"),
		Action:      r.FormValue("rule_action"),
		Position:    position,
		Protocol:    r.FormValue("protocol"),
		InInterface: r.FormValue("in_interface"),
		OutInterface:r.FormValue("out_interface"),
		SourceIP:    r.FormValue("source_ip"),
		DestIP:      r.FormValue("dest_ip"),
		SourcePort:  sourcePort,
		DestPort:    port,
		ConnState:   r.FormValue("conn_state"),
		IcmpType:    r.FormValue("icmp_type"),
		Target:      r.FormValue("target"),
		LogPrefix:   r.FormValue("log_prefix"),
		LogLevel:    r.FormValue("log_level"),
		RejectWith:  r.FormValue("reject_with"),
		ExtraArgs:   parseArgs(r.FormValue("extra_args")),
	}

	if spec.Table == "" || spec.Chain == "" {
		if ruleType == "dnat" {
			spec.Table = "nat"
			spec.Chain = "PREROUTING"
		} else {
			spec.Table = "filter"
			spec.Chain = "INPUT"
		}
	}

    switch ruleType {

    case "connlimit":
        limit, _ := strconv.Atoi(r.FormValue("conn_limit"))
        spec.ConnLimit = &limit
        spec.Comment = fmt.Sprintf("GoResolver:%s:CONNLIMIT_%d", spec.SourceIP, port)

    case "ratelimit":
        spec.LimitRate = r.FormValue("rate")
        spec.LimitBurst = r.FormValue("burst")
        spec.Comment = fmt.Sprintf("GoResolver:%s:RATELIMIT", spec.SourceIP)

    case "syn":
        spec.LimitRate = r.FormValue("rate")
        spec.LimitBurst = r.FormValue("burst")
        spec.SynOnly = true
        spec.Comment = fmt.Sprintf("GoResolver:%s:SYN", spec.SourceIP)

	case "dnat":
		spec.ToIP = r.FormValue("to_ip")
		spec.ToPort = toPort
		spec.Target = "DNAT"
		spec.Comment = fmt.Sprintf("GoResolver:DNAT:%d", port)

	case "masquerade":
		spec.Target = "MASQUERADE"
		spec.Table = "nat"
		spec.Chain = "POSTROUTING"
		spec.Comment = "GoResolver:MASQUERADE"

    case "block":
        spec.Target = "DROP"
        spec.Comment = "GoResolver:" + spec.SourceIP + ":BLOCK"

    case "allow":
        spec.Target = "ACCEPT"
        spec.Comment = "GoResolver:" + spec.SourceIP + ":ALLOW"
    }

	userComment := strings.TrimSpace(r.FormValue("rule_comment"))
	spec.Comment = withRuleComment(spec.Comment, mux.Vars(r)["id"], ruleType, userComment)

    if err := h.Service.AddRule(spec); err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    redirectWithTab(w, r, mux.Vars(r)["id"], "tab6")
}

func withRuleComment(base, serverID, ruleType, userComment string) string {
	trimmed := sanitizeComment(userComment)
	if base == "" {
		base = fmt.Sprintf("GoResolver:%s:%s", serverID, ruleType)
	}
	if trimmed != "" {
		base = base + ":" + trimmed
	}
	return fmt.Sprintf("%s:%d", base, time.Now().UnixNano())
}

func sanitizeComment(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if len(input) > 80 {
		input = input[:80]
	}
	// Strip control characters to keep iptables comment safe.
	var b strings.Builder
	for _, r := range input {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func parseArgs(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var args []string
	var current strings.Builder
	var inSingle, inDouble, escaping bool

	for _, r := range input {
		switch {
		case escaping:
			current.WriteRune(r)
			escaping = false
		case r == '\\':
			escaping = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case r == ' ' || r == '\t' || r == '\n':
			if inSingle || inDouble {
				current.WriteRune(r)
				continue
			}
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func (h *ServerConfigurationHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()

    table := r.FormValue("table")
    chain := r.FormValue("chain")
    comment := r.FormValue("comment")

    if table == "" || chain == "" || comment == "" {
        http.Error(w, "Missing rule identifier", http.StatusBadRequest)
        return
    }

    if err := h.Service.DeleteRuleByComment(chain, table, comment); err != nil {
        log.Println("Delete rule failed:", err)
        http.Error(w, "Failed to delete rule: "+err.Error(), http.StatusInternalServerError)
        return
    }

    redirectWithTab(w, r, mux.Vars(r)["id"], "tab6")
}

func extractPort(comment string) string {
    parts := strings.Split(comment, ":")
    if len(parts) == 3 {
        return strings.TrimPrefix(parts[2], "CONNLIMIT_")
    }
    return ""
}

func isGoResolverRule(comment string) bool {
    return strings.HasPrefix(comment, "GoResolver:")
}

func extractLimit(rule models.IPTablesRule) string {
    return rule.Limit
}

func (h *ServerConfigurationHandler) CreateVPNConfig(w http.ResponseWriter, r *http.Request) {
    serverID := mux.Vars(r)["id"]
    if serverID == "" {
        http.Error(w, "No server id supplied", http.StatusBadRequest)
        return
    }

	vpn_ip := r.FormValue("vpn_ip")
	if vpn_ip == "" {
		http.Error(w, "No VPN-IP set", http.StatusBadRequest)
		return
	}

	pass := r.FormValue("pass")
	if pass == "" {
		http.Error(w, "Passphrase required", http.StatusBadRequest)
		return 
	}

    clientName := fmt.Sprintf("client-%s", serverID)

    config, err := h.Service.GenerateVPNClientConfig(serverID, clientName, pass)
    if err != nil {
        http.Error(w, "Failed to generate VPN config: "+err.Error(), http.StatusInternalServerError)
        return
    }

    err = h.Service.SaveVPNConfig(serverID, []byte(config))
    if err != nil {
        http.Error(w, "Failed to save VPN config: "+err.Error(), http.StatusInternalServerError)
        return
    }

	err = h.Service.AssignStaticVPNIP(clientName, vpn_ip)
	if err != nil {
		http.Error(w, "Failed to assign static ip:"+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.Service.UpdateServerIP(serverID, vpn_ip); err != nil {
		http.Error(w, "Failed to update server ip:"+err.Error(), http.StatusInternalServerError)
		return
	}

	redirectWithTab(w, r, mux.Vars(r)["id"], "tab2")
}

func (h *ServerConfigurationHandler) UpdateDDoS(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		http.Error(w, "No server id supplied", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	if err := h.applyDDoSFromForm(r, serverID); err != nil {
		http.Error(w, "Failed to apply DDoS policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	redirectWithTab(w, r, serverID, "tab7")
}

func (h *ServerConfigurationHandler) applyDDoSFromForm(r *http.Request, serverID string) error {
	enabled := r.FormValue("ddos_enabled") == "1"
	mode := r.FormValue("ddos_mode")
	preset := r.FormValue("ddos_preset")
	whitelist := strings.TrimSpace(r.FormValue("ddos_whitelist"))

	rateLimit, _ := strconv.Atoi(r.FormValue("ddos_rate_limit"))
	burst, _ := strconv.Atoi(r.FormValue("ddos_burst"))
	connLimit, _ := strconv.Atoi(r.FormValue("ddos_conn_limit"))
	synRate, _ := strconv.Atoi(r.FormValue("ddos_syn_rate"))
	synBurst, _ := strconv.Atoi(r.FormValue("ddos_syn_burst"))
	challengeDelay, _ := strconv.Atoi(r.FormValue("ddos_challenge_delay"))
	cookieTTL, _ := strconv.Atoi(r.FormValue("ddos_cookie_ttl"))

	if preset != "custom" {
		switch preset {
		case "low":
			rateLimit = 20
			burst = 40
			connLimit = 100
			synRate = 20
			synBurst = 40
		case "high":
			rateLimit = 5
			burst = 10
			connLimit = 25
			synRate = 5
			synBurst = 10
		default:
			preset = "medium"
			rateLimit = 10
			burst = 20
			connLimit = 50
			synRate = 10
			synBurst = 20
		}
	}

	if challengeDelay <= 0 {
		challengeDelay = 5
	}
	if cookieTTL <= 0 {
		cookieTTL = 3600
	}

	policy := models.DDoSPolicy{
		ServerID:       serverID,
		Enabled:        enabled,
		Mode:           mode,
		Preset:         preset,
		RateLimit:      rateLimit,
		Burst:          burst,
		ConnLimit:      connLimit,
		SynRate:        synRate,
		SynBurst:       synBurst,
		ChallengeDelay: challengeDelay,
		CookieTTL:      cookieTTL,
		Whitelist:      whitelist,
	}

	if err := h.Service.SaveDDoSPolicy(policy); err != nil {
		return err
	}

	if err := h.Service.ApplyDDoSIptables(serverID, policy); err != nil {
		return err
	}

	conf := h.Service.GetServerConfiguration(serverID)
	seen := map[string]bool{}
	for _, c := range conf {
		if c.Server_Name == "" || seen[c.Server_Name] {
			continue
		}
		seen[c.Server_Name] = true
		if err := services.DeployNginxConfig(c.Server_Name); err != nil {
			log.Println("nginx deploy failed:", err)
		}
	}

	return nil
}

func (h *ServerConfigurationHandler) applyFail2BanFromForm(r *http.Request, serverID string) error {
	enabled := r.FormValue("fail2ban_enabled") == "1"
	maxRetry, _ := strconv.Atoi(r.FormValue("fail2ban_max_retry"))
	findTime, _ := strconv.Atoi(r.FormValue("fail2ban_find_time"))
	banTime, _ := strconv.Atoi(r.FormValue("fail2ban_ban_time"))
	statusCodes := strings.TrimSpace(r.FormValue("fail2ban_status_codes"))
	ignoreIPs := strings.TrimSpace(r.FormValue("fail2ban_ignore_ips"))
	useXff := r.FormValue("fail2ban_use_xff") == "1"
	banGlobally := r.FormValue("fail2ban_ban_globally") == "1"

	policy := models.Fail2BanPolicy{
		ServerID:         serverID,
		Enabled:          enabled,
		MaxRetry:         maxRetry,
		FindTimeSeconds:  findTime,
		BanTimeSeconds:   banTime,
		StatusCodes:      statusCodes,
		IgnoreIPs:        ignoreIPs,
		UseXForwardedFor: useXff,
		BanGlobally:      banGlobally,
	}

	if err := h.Service.SaveFail2BanPolicy(policy); err != nil {
		return err
	}
	if enabled {
		h.Service.EnforceFail2BanOnce()
	}
	return nil
}

func (h *ServerConfigurationHandler) UnbanFail2Ban(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		http.Error(w, "No server id supplied", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(r.FormValue("fail2ban_ip"))
	if ip == "" {
		http.Error(w, "Missing IP", http.StatusBadRequest)
		return
	}
	if err := h.Service.UnbanFail2BanIP(serverID, ip); err != nil {
		http.Error(w, "Failed to unban IP: "+err.Error(), http.StatusInternalServerError)
		return
	}
	redirectWithTab(w, r, serverID, "tab8")
}


func redirectWithTab(w http.ResponseWriter, r *http.Request, serverID, tab string) {


	redirectURL := "/servers/" + serverID + "/server_configuration"
	if tab != "" {
		redirectURL += "?tab=" + url.QueryEscape(tab) + "&t=" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	//http.Redirect(w, r, redirectURL, http.StatusFound)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}
