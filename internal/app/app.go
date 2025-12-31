package app


import (
	"log"
	"net/http"
)


type App struct {
	Router http.Handler
}


func New() *App {
	a := &App{}
	a.Router = NewRouter()
	return a
}


func (a *App) Run() {
	log.Println("Server running on http://localhost:8888")
	http.ListenAndServe(":8888", a.Router)
}
