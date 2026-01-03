package handlers

import (
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"net/url"
	"io"
	"fmt"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

type ServerConfigurationHandler struct {
	Tmpl    *template.Template
	Service *services.ServerConfigurationService
}

func NewServerConfigurationHandler() *ServerConfigurationHandler {
	funcMap := template.FuncMap{
		"extractPort":  extractPort,
		"extractLimit": extractLimit,
		"contains":     contains,
	}

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
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}

func (h *ServerConfigurationHandler) Index(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}

	conf := h.Service.GetServerConfiguration(serverID)
	if len(conf) == 0 {
		http.Error(w, "No server config found", http.StatusNotFound)
	}
	
	errorPages := h.Service.GetServerErrorPages(serverID)
	errorFiles := h.Service.GetServerErrorFiles()

	vpnText := ""
	if len(conf[0].VPN_File) > 0 {
		vpnText = string(conf[0].VPN_File) 
	}

	page := models.PageDataServerConfig{
		Active:     "servers",
		Data:       conf,
		ServerID:   serverID,
		ServerName: conf[0].Name,
		IP:         conf[0].IP,
		VPN_File:   vpnText, 
		ErrorPages: errorPages,
		ErrorFiles: errorFiles,
	}
	rules, err := h.Service.ListIPTablesRules()
	rulesForServer := FilterRulesForServer(rules, "87.106.24.216" ,conf[0].IP)
	if err != nil {
		log.Println("iptables error:", err)
	} else {
		page.IPTablesRules = rulesForServer
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}



func (h *ServerConfigurationHandler) Update(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	ids := r.Form["id[]"]
	topServerName := r.FormValue("top_server_name")
	vpnText := r.FormValue("vpn_file")
	vpnBytes := []byte(vpnText)

	serverNames := r.Form["server_name[]"]
	serverPorts := r.Form["server_port[]"]
	sslEnabled := r.Form["ssl_enabled[]"]
	sslRedirect := r.Form["ssl_redirect[]"]
	proxyPassPorts := r.Form["proxy_pass_port[]"]
	proxyErrors := r.Form["proxy_intercept_errors[]"]
	websocketsEnabled := r.Form["Websockets[]"]

	for i := range ids {
		serverName := strings.TrimSpace(serverNames[i])
		if ids[i] == "" && serverName == "" {
			continue
		}

		id, _ := strconv.Atoi(ids[i])
		serverPort, _ := strconv.Atoi(serverPorts[i])
		ssl, _ := strconv.Atoi(sslEnabled[i])
		ssl_redirect, _ := strconv.Atoi(sslRedirect[i])
		proxyPort, _ := strconv.Atoi(proxyPassPorts[i])
		proxyErr, _ := strconv.Atoi(proxyErrors[i])
		websockets, _ := strconv.Atoi(websocketsEnabled[i])

		if ids[i] == "" {
			// INSERT new server config
			err := h.Service.InsertServerConfiguration(models.ServerConfiguration{
				ServerID:               serverID,
				Server_Name:            serverNames[i],
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
				ServerID:               serverID,
				Server_Name:            serverNames[i],
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

	n := max(len(epIDs), len(efIDs), len(epSiteIDs), len(epEnabledArr))

	for i := 0; i < n; i++ {
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

	for i := 0; i < len(efID); i++ {
		if efID[i] == "" {
			continue
		}

		err := h.Service.UpdateErrorFiles(models.ServerErrorFiles{
			ID:           efID[i],
			Error_Code:   efErrorCodes[i],
			ResponseType: efResponseTypes[i],
		})

		if err != nil {
			log.Println("Update error files failed:", err)
			http.Error(w, "Update failed", http.StatusInternalServerError)
			return
		}
	}

	tab := r.FormValue("active_tab")
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
	path := "/var/www/error_pages"

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

	serverName := r.FormValue("serverName")
	id := r.FormValue("id")

	err := h.Service.RenewCert(id, serverName)

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
	serverName := r.FormValue("serverName")
	id := r.FormValue("id")

	err := h.Service.DeleteCert(id, serverName)

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

func FilterRulesForServer(rules []models.IPTablesRule, serverIPs ...string) []models.IPTablesRule {
    var filtered []models.IPTablesRule

    ipSet := make(map[string]bool)
    for _, ip := range serverIPs {
        ipSet[ip] = true
    }

    for _, r := range rules {
        if ipSet[r.Source] || ipSet[r.Destination] {
            filtered = append(filtered, r)
        }
    }

    return filtered
}

func (h *ServerConfigurationHandler) AddRule(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()

    ruleType := r.FormValue("rule_type")

    port, _ := strconv.Atoi(r.FormValue("port"))
    toPort, _ := strconv.Atoi(r.FormValue("to_port"))

    spec := models.IPTablesRuleSpec{
        Table:    r.FormValue("table"),
        Chain:    r.FormValue("chain"),
        Protocol: r.FormValue("protocol"),
        SourceIP: r.FormValue("source_ip"),
        DestIP:   r.FormValue("dest_ip"),
        DestPort: port,
        Target:   r.FormValue("target"),
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

    case "block":
        spec.Target = "DROP"
        spec.Comment = "GoResolver:" + spec.SourceIP + ":BLOCK"

    case "allow":
        spec.Target = "ACCEPT"
        spec.Comment = "GoResolver:" + spec.SourceIP + ":ALLOW"
    }

    if err := h.Service.AddRule(spec); err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    redirectWithTab(w, r, mux.Vars(r)["id"], "tab6")
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

	redirectWithTab(w, r, mux.Vars(r)["id"], "tab2")
}


func redirectWithTab(w http.ResponseWriter, r *http.Request, serverID, tab string) {
	redirectURL := "/servers/" + serverID + "/server_configuration"
	if tab != "" {
		redirectURL += "?tab=" + url.QueryEscape(tab)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}