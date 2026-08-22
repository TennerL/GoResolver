package handlers

import (
	"net"
	"net/http"
	"net/url"
	"strings"

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

	ip := loginClientIP(r)
	auth := h.Service.Authenticate(username, password, ip)
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

// loginClientIP trusts forwarding headers only from the local reverse proxy.
// The right-most X-Forwarded-For entry is the address nginx appended itself;
// using the first entry would allow clients to spoof their address.
func loginClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP := net.ParseIP(strings.Trim(remote, "[]"))
	if remoteIP == nil || !remoteIP.IsLoopback() {
		return remote
	}

	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(forwarded[i])
		if parsed := net.ParseIP(strings.Trim(candidate, "[]")); parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
			return parsed.String()
		}
	}
	if candidate := net.ParseIP(strings.Trim(strings.TrimSpace(r.Header.Get("X-Real-IP")), "[]")); candidate != nil && !candidate.IsLoopback() && !candidate.IsUnspecified() {
		return candidate.String()
	}
	return remote
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
