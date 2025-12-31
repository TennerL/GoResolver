package app

import (
	"net/http"
	"GoResolver/internal/session"
)

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := session.Store.Get(r, "session")
		if err != nil {
			http.Error(w, "Session error", 500)
			return
		}

		auth, ok := sess.Values["authenticated"].(bool)
		if !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
