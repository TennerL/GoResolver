package handlers

import (
	"errors"
	"net/http"

	"GoResolver/internal/models"
	"github.com/gorilla/mux"
)

func (h *ServerConfigurationHandler) BuildPage(r *http.Request) (models.PageDataServerConfig, int, error) {
	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		return models.PageDataServerConfig{}, http.StatusBadRequest, errors.New("no id supplied")
	}

	conf := h.Service.GetServerConfiguration(serverID)
	policy, _ := h.Service.GetDDoSPolicy(serverID)
	fail2banPolicy, _ := h.Service.GetFail2BanPolicy(serverID)
	fail2banBans := h.Service.ListFail2BanBans(serverID)

	if len(conf) == 0 {
		srv, err := h.Service.GetServerBasics(serverID)
		if err != nil {
			return models.PageDataServerConfig{}, http.StatusNotFound, errors.New("no server config found")
		}

		page := models.PageDataServerConfig{
			Active:         "servers",
			View:           "serverconfiguration",
			Data:           []models.ServerConfiguration{},
			ServerID:       serverID,
			ServerName:     srv.Name,
			IP:             srv.IP,
			VPN_File:       srv.VPN_File,
			ErrorPages:     h.Service.GetServerErrorPages(serverID),
			ErrorFiles:     h.Service.GetServerErrorFiles(),
			DDoSPolicy:     policy,
			Fail2BanPolicy: fail2banPolicy,
			Fail2BanBans:   fail2banBans,
		}

		if srv.IP != "" {
			rules, err := h.Service.ListIPTablesRules()
			if err == nil {
				page.IPTablesRules = FilterRulesForServer(rules, serverID, srv.IP)
			}
		}

		return page, http.StatusOK, nil
	}

	errorPages := h.Service.GetServerErrorPages(serverID)
	errorFiles := h.Service.GetServerErrorFiles()
	vpnText := string(conf[0].VPN_File)

	page := models.PageDataServerConfig{
		Active:         "servers",
		View:           "serverconfiguration",
		Data:           conf,
		ServerID:       serverID,
		ServerName:     conf[0].Name,
		IP:             conf[0].IP,
		VPN_File:       vpnText,
		ErrorPages:     errorPages,
		ErrorFiles:     errorFiles,
		DDoSPolicy:     policy,
		Fail2BanPolicy: fail2banPolicy,
		Fail2BanBans:   fail2banBans,
	}

	rules, err := h.Service.ListIPTablesRules()
	if err == nil {
		page.IPTablesRules = FilterRulesForServer(rules, serverID, conf[0].IP)
	}

	return page, http.StatusOK, nil
}

func (h *ServerConfigurationHandler) API(w http.ResponseWriter, r *http.Request) {
	page, status, err := h.BuildPage(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	writeJSON(w, http.StatusOK, page)
}
