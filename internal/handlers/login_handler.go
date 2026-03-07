package handlers

import (
	"net/http"
	"net/url"

	"GoResolver/internal/services"
	"GoResolver/internal/session"
)

type LoginHandler struct {
	Service *services.LoginService
}

func NewLoginHandler() *LoginHandler {
	return &LoginHandler{
		Service: services.NewLoginService(),
	}
}

func (h *LoginHandler) Index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	auth := h.Service.Authenticate(username, password)
	if !auth.Success {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(auth.Error), http.StatusSeeOther)
		return
	}

	sess, err := session.Get(r, "session")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	sess.Values["authenticated"] = true
	sess.Values["userid"] = auth.UserID
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "Session save error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, err := session.Get(r, "session")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	sess.Options.MaxAge = -1
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "Session save error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
