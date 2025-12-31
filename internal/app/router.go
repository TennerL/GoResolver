package app

import (
	"net/http"

	"GoResolver/internal/handlers"
	"github.com/gorilla/mux"
)

func NewRouter() http.Handler {
	r := mux.NewRouter()


	dashboard := handlers.NewDashboardHandler()
	domains := handlers.NewDomainsHandler()
	records := handlers.NewRecordHandler()
	servers := handlers.NewServerHandler()
	serverconfiguration := handlers.NewServerConfigurationHandler()
	login := handlers.NewLoginHandler()

	r.HandleFunc("/login", login.Index).Methods("GET", "POST")
	r.HandleFunc("/logout", login.Logout).Methods("GET", "POST")
	r.HandleFunc("/", RequireAuth(dashboard.Index)).Methods("GET")
	// Domains
	r.HandleFunc("/domains", RequireAuth(domains.Index)).Methods("GET")
	r.HandleFunc("/domains/new", RequireAuth(domains.Create)).Methods("POST")
	r.HandleFunc("/domains/{id:[0-9]+}/delete", RequireAuth(domains.Delete)).Methods("POST")
	r.HandleFunc("/domains/{id:[0-9]+}/records", RequireAuth(records.Index)).Methods("GET")
	r.HandleFunc("/domains/{id:[0-9]+}/records/new", RequireAuth(records.Create)).Methods("POST")
	// Records
	r.HandleFunc("/records/{id}/edit", RequireAuth(records.Edit)).Methods("POST")
	r.HandleFunc("/records/{id}/delete", RequireAuth(records.Delete)).Methods("POST")
	// Servers 
	r.HandleFunc("/servers", RequireAuth(servers.Index)).Methods("GET")
	r.HandleFunc("/servers/{id:[0-9]+}/server_configuration", RequireAuth(serverconfiguration.Index)).Methods("GET")
	r.HandleFunc(
		"/servers/{id:[0-9]+}/server_configuration",
		RequireAuth(serverconfiguration.HandlePost),
	).Methods("POST")
	r.HandleFunc("/servers/{id:[0-9]+}/error-pages/upload", RequireAuth(serverconfiguration.UploadErrorPage)).Methods("POST")
	r.HandleFunc("/error-files/{id}", RequireAuth(serverconfiguration.GetErrorFile)).Methods("GET")
	r.HandleFunc("/error-files/{id}", RequireAuth(serverconfiguration.UpdateErrorFile)).Methods("PUT")




	r.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("web/static"))))

	return r
}
