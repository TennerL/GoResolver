package handlers

import (
	"html/template"
	"net/http"

	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"GoResolver/internal/session"

)

type LoginHandler struct {
	Tmpl    *template.Template
	Service *services.LoginService
}

func NewLoginHandler() *LoginHandler {
	return &LoginHandler{
		Tmpl: parseTemplatesWithFuncMap(
			baseFuncMap(),
			"web/templates/layout.html",
			"web/templates/login.html",
		),
		Service: services.NewLoginService(),
	}
}

func (h *LoginHandler) Index(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		auth := h.Service.Authenticate(username, password)
		if !auth.Success {
			data["Error"] = auth.Error
			h.render(w, data)
			return
		}

		sess, err := session.Store.Get(r, "session")
		if err != nil {
			http.Error(w, "Session error", 500)
			return
		}

		sess.Values["authenticated"] = true
		sess.Values["userid"] = auth.UserID
		sess.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.render(w, data)
}

func (h *LoginHandler) render(w http.ResponseWriter, data map[string]string) {
	h.Tmpl.ExecuteTemplate(w, "layout", models.PageData{
		Active: "login",
		Data:   data,
	})
}

func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := session.Store.Get(r, "session")
	sess.Options.MaxAge = -1
	sess.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
