package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"GoResolver/internal/models"
	"github.com/gorilla/mux"
)

type serverConfigurationUpdateData struct {
	topServerName       string
	vpnIP               string
	vpnBytes            []byte
	ids                 []string
	serverNames         []string
	serverPorts         []string
	sslEnabled          []string
	sslRedirect         []string
	hstsEnabled         []string
	proxyPassPorts      []string
	proxyErrors         []string
	websocketsEnabled   []string
	errorPageIDs        []string
	errorPageSiteIDs    []string
	errorPageFileIDs    []string
	errorPageEnabled    []string
	errorPageFileRowIDs []string
	errorFileCodes      []string
	errorFileTypes      []string
}

type serverConfigurationRow struct {
	id          string
	name        string
	port        int
	sslEnabled  int
	sslRedirect int
	hsts        int
	proxyPort   int
	proxyErrors int
	websockets  int
}

type serverErrorPageRow struct {
	id          string
	siteID      string
	errorFileID string
	enabled     bool
}

type serverErrorFileRow struct {
	id           string
	errorCode    string
	responseType string
}

func loadServerConfigurationUpdateData(r *http.Request) serverConfigurationUpdateData {
	vpnText := r.FormValue("vpn_file")

	return serverConfigurationUpdateData{
		topServerName:       r.FormValue("top_server_name"),
		vpnIP:               strings.TrimSpace(r.FormValue("vpn_ip")),
		vpnBytes:            []byte(vpnText),
		ids:                 r.Form["id[]"],
		serverNames:         r.Form["server_name[]"],
		serverPorts:         r.Form["server_port[]"],
		sslEnabled:          r.Form["ssl_enabled[]"],
		sslRedirect:         r.Form["ssl_redirect[]"],
		hstsEnabled:         r.Form["hsts[]"],
		proxyPassPorts:      r.Form["proxy_pass_port[]"],
		proxyErrors:         r.Form["proxy_intercept_errors[]"],
		websocketsEnabled:   r.Form["Websockets[]"],
		errorPageIDs:        r.Form["error_page_id[]"],
		errorPageSiteIDs:    r.Form["site_id[]"],
		errorPageFileIDs:    r.Form["error_file_id[]"],
		errorPageEnabled:    r.Form["enabled[]"],
		errorPageFileRowIDs: r.Form["error_page_file_id[]"],
		errorFileCodes:      r.Form["error_code[]"],
		errorFileTypes:      r.Form["response_type[]"],
	}
}

func (d serverConfigurationUpdateData) serverConfigurationRowAt(i int) serverConfigurationRow {
	return serverConfigurationRow{
		id:          valueAt(d.ids, i),
		name:        strings.TrimSpace(valueAt(d.serverNames, i)),
		port:        atoiOrZero(valueAt(d.serverPorts, i)),
		sslEnabled:  atoiOrZero(valueAt(d.sslEnabled, i)),
		sslRedirect: atoiOrZero(valueAt(d.sslRedirect, i)),
		hsts:        atoiOrZero(valueAt(d.hstsEnabled, i)),
		proxyPort:   atoiOrZero(valueAt(d.proxyPassPorts, i)),
		proxyErrors: atoiOrZero(valueAt(d.proxyErrors, i)),
		websockets:  atoiOrZero(valueAt(d.websocketsEnabled, i)),
	}
}

func (d serverConfigurationUpdateData) serverErrorPageRowAt(i int) serverErrorPageRow {
	return serverErrorPageRow{
		id:          valueAt(d.errorPageIDs, i),
		siteID:      valueAt(d.errorPageSiteIDs, i),
		errorFileID: valueAt(d.errorPageFileIDs, i),
		enabled:     valueAt(d.errorPageEnabled, i) == "1",
	}
}

func (d serverConfigurationUpdateData) serverErrorFileRowAt(i int) serverErrorFileRow {
	return serverErrorFileRow{
		id:           valueAt(d.errorPageFileRowIDs, i),
		errorCode:    strings.TrimSpace(valueAt(d.errorFileCodes, i)),
		responseType: strings.TrimSpace(valueAt(d.errorFileTypes, i)),
	}
}

func (row serverConfigurationRow) empty() bool {
	return row.id == "" && row.name == ""
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

func atoiOrZero(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))
	return value
}

func (h *ServerConfigurationHandler) Update(w http.ResponseWriter, r *http.Request) {
	if err := parseServerConfigurationForm(r); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	serverID := mux.Vars(r)["id"]
	tab := r.FormValue("active_tab")
	updateData := loadServerConfigurationUpdateData(r)

	if err := h.saveServerConfigurationRows(serverID, updateData); err != nil {
		log.Println("Save server configuration failed:", err)
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	if err := h.saveServerErrorPages(serverID, updateData); err != nil {
		log.Println("Save error pages failed:", err)
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	if err := h.saveServerErrorFiles(updateData); err != nil {
		log.Println("Update error files failed:", err)
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	if err := h.applyDDoSFromForm(r, serverID); err != nil {
		http.Error(w, "Failed to apply DDoS policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.applyFail2BanFromForm(r, serverID); err != nil {
		http.Error(w, "Failed to apply Fail2Ban policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.assignStaticVPNIP(serverID, updateData.vpnIP); err != nil {
		log.Println("Update VPN IP failed:", err)
		http.Error(w, "Update VPN IP failed", http.StatusInternalServerError)
		return
	}

	redirectWithTab(w, r, serverID, tab)
}

func (h *ServerConfigurationHandler) saveServerConfigurationRows(serverID string, updateData serverConfigurationUpdateData) error {
	rowCount := maxLen(
		updateData.ids,
		updateData.serverNames,
		updateData.serverPorts,
		updateData.sslEnabled,
		updateData.sslRedirect,
		updateData.hstsEnabled,
		updateData.proxyPassPorts,
		updateData.proxyErrors,
		updateData.websocketsEnabled,
	)

	for i := 0; i < rowCount; i++ {
		row := updateData.serverConfigurationRowAt(i)
		if row.empty() {
			continue
		}

		config := models.ServerConfiguration{
			ServerID:               serverID,
			Server_Name:            row.name,
			Server_Port:            row.port,
			SSL_Enabled:            row.sslEnabled,
			SSL_Redirect:           row.sslRedirect,
			HSTS:                   row.hsts,
			Proxy_Pass_Port:        row.proxyPort,
			Proxy_Intercept_Errors: row.proxyErrors,
			Websockets:             row.websockets,
		}

		var err error
		if row.id == "" {
			err = h.Service.InsertServerConfiguration(config)
		} else {
			config.ID = atoiOrZero(row.id)
			config.Name = updateData.topServerName
			config.IP = updateData.vpnIP
			config.VPN_File = updateData.vpnBytes
			err = h.Service.UpdateServerConfiguration(config)
		}
		if err != nil {
			return err
		}

		log.Printf("saved server configuration row existing_id=%q name=%s", row.id, row.name)
	}

	return nil
}

func (h *ServerConfigurationHandler) saveServerErrorPages(serverID string, updateData serverConfigurationUpdateData) error {
	rowCount := maxLen(
		updateData.errorPageIDs,
		updateData.errorPageFileIDs,
		updateData.errorPageSiteIDs,
		updateData.errorPageEnabled,
	)

	for i := 0; i < rowCount; i++ {
		row := updateData.serverErrorPageRowAt(i)
		if row.errorFileID == "" {
			continue
		}

		errorPage := models.ServerErrorPages{
			ID:           row.id,
			Server_ID:    serverID,
			Site_ID:      row.siteID,
			ErrorPage_ID: row.errorFileID,
			Enabled:      row.enabled,
		}

		var err error
		if row.id == "" {
			err = h.Service.InsertErrorPage(errorPage)
		} else {
			err = h.Service.SaveErrorPage(errorPage)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *ServerConfigurationHandler) saveServerErrorFiles(updateData serverConfigurationUpdateData) error {
	rowCount := maxLen(updateData.errorPageFileRowIDs, updateData.errorFileCodes, updateData.errorFileTypes)

	for i := 0; i < rowCount; i++ {
		row := updateData.serverErrorFileRowAt(i)
		if row.id == "" || row.errorCode == "" || row.responseType == "" {
			continue
		}

		if err := h.Service.UpdateErrorFiles(models.ServerErrorFiles{
			ID:           row.id,
			Error_Code:   row.errorCode,
			ResponseType: row.responseType,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *ServerConfigurationHandler) assignStaticVPNIP(serverID, vpnIP string) error {
	if vpnIP == "" {
		return nil
	}

	clientName := fmt.Sprintf("client-%s", serverID)
	return h.Service.AssignStaticVPNIP(clientName, vpnIP)
}
