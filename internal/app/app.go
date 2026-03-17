package app

import (
	"log"
	"net/http"
	"strings"

	"GoResolver/internal/services"
)

type App struct {
	Router http.Handler
}

func New() *App {
	a := &App{}
	services.StartStatusMonitor()
	a.Router = NewRouter()
	return a
}

func (a *App) Run() error {
	settings := services.NewSettingsService()
	baseURL := settings.GetValue("app.base_url")
	listenAddr := settings.GetValue("app.listen_addr")
	if listenAddr == "" {
		listenAddr = ":8888"
	}
	if baseURL == "" {
		if strings.HasPrefix(listenAddr, ":") {
			baseURL = "http://localhost" + listenAddr
		} else {
			baseURL = "http://localhost:8888"
		}
	}
	log.Println("Server running on", baseURL)
	return http.ListenAndServe(listenAddr, a.Router)
}
