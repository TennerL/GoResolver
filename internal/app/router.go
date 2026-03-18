package app

import (
	"io/fs"
	"log"
	"net/http"

	"GoResolver/internal/handlers"
	"GoResolver/web"
	"github.com/gorilla/mux"
)

func NewRouter() http.Handler {
	r := mux.NewRouter()

	frontend := handlers.NewFrontendHandler()
	dashboard := handlers.NewDashboardHandler()
	domains := handlers.NewDomainsHandler()
	records := handlers.NewRecordHandler()
	servers := handlers.NewServerHandler()
	serverconfiguration := handlers.NewServerConfigurationHandler()
	login := handlers.NewLoginHandler()
	analyticsHandler := handlers.NewAnalyticsHandler()
	settingsHandler := handlers.NewSettingsHandler()

	r.HandleFunc("/login", frontend.Index).Methods("GET")
	r.HandleFunc("/login", login.Index).Methods("POST")
	r.HandleFunc("/logout", login.Logout).Methods("GET", "POST")

	r.HandleFunc("/", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/domains", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/domains/{id:[0-9]+}/records", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/servers", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/servers/{id:[0-9]+}/server_configuration", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/analytics", RequireAuth(frontend.Index)).Methods("GET")
	r.HandleFunc("/settings", RequireAuth(frontend.Index)).Methods("GET")

	r.HandleFunc("/api/pages/dashboard", RequireAuthAPI(dashboard.API)).Methods("GET")
	r.HandleFunc("/api/pages/domains", RequireAuthAPI(domains.API)).Methods("GET")
	r.HandleFunc("/api/pages/domains/{id:[0-9]+}/records", RequireAuthAPI(records.API)).Methods("GET")
	r.HandleFunc("/api/pages/servers", RequireAuthAPI(servers.API)).Methods("GET")
	r.HandleFunc("/api/pages/servers/{id:[0-9]+}/server_configuration", RequireAuthAPI(serverconfiguration.API)).Methods("GET")
	r.HandleFunc("/api/pages/settings", RequireAuthAPI(settingsHandler.API)).Methods("GET")

	r.HandleFunc("/domains/new", RequireAuth(domains.Create)).Methods("POST")
	r.HandleFunc("/domains/{id:[0-9]+}/delete", RequireAuth(domains.Delete)).Methods("POST")
	r.HandleFunc("/domains/{id:[0-9]+}/records/new", RequireAuth(records.Create)).Methods("POST")
	r.HandleFunc("/records/{id}/edit", RequireAuth(records.Edit)).Methods("POST")
	r.HandleFunc("/records/{id}/delete", RequireAuth(records.Delete)).Methods("POST")

	r.HandleFunc("/servers/new", RequireAuth(servers.AddServer)).Methods("POST")
	r.HandleFunc("/servers/{id:[0-9]+}/delete", RequireAuth(servers.Delete)).Methods("POST")
	r.HandleFunc("/servers/{id:[0-9]+}/server_configuration", RequireAuth(serverconfiguration.HandlePost)).Methods("POST")
	r.HandleFunc("/servers/{id:[0-9]+}/error-pages/upload", RequireAuth(serverconfiguration.UploadErrorPage)).Methods("POST")
	r.HandleFunc("/error-files/{id}", RequireAuth(serverconfiguration.GetErrorFile)).Methods("GET")
	r.HandleFunc("/error-files/{id}", RequireAuth(serverconfiguration.UpdateErrorFile)).Methods("PUT")

	r.HandleFunc("/api/analytics", RequireAuthAPI(analyticsHandler.API)).Methods("GET")
	r.HandleFunc("/api/analytics/alerts", RequireAuthAPI(analyticsHandler.Alerts)).Methods("GET")
	r.HandleFunc("/api/analytics/hosts", RequireAuthAPI(analyticsHandler.Hosts)).Methods("GET")
	r.HandleFunc("/api/analytics/incidents", RequireAuthAPI(analyticsHandler.Incidents)).Methods("GET")
	r.HandleFunc("/api/analytics/incidents/{id:[0-9]+}/dismiss", RequireAuthAPI(analyticsHandler.DismissIncident)).Methods("POST")
	r.HandleFunc("/api/analytics/ips", RequireAuthAPI(analyticsHandler.IPs)).Methods("GET")
	r.HandleFunc("/api/analytics/ip-geo", RequireAuthAPI(analyticsHandler.IPGeo)).Methods("GET")
	r.HandleFunc("/api/analytics/logs", RequireAuthAPI(analyticsHandler.Logs)).Methods("GET")
	r.HandleFunc("/api/analytics/ip-profile", RequireAuthAPI(analyticsHandler.IPProfile)).Methods("GET")
	r.HandleFunc("/settings", RequireAuth(settingsHandler.Index)).Methods("POST")
	r.HandleFunc("/api/settings/test_mail", RequireAuthAPI(settingsHandler.SendTestMail)).Methods("POST")

	static, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		log.Printf("static asset filesystem unavailable: %v", err)
		return r
	}

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	return r
}
