package app

import (
	"net/http"

	"GoResolver/internal/session"
)

func isAuthenticated(r *http.Request) (bool, error) {
	sess, err := session.Get(r, "session")
	if err != nil {
		return false, err
	}

	auth, ok := sess.Values["authenticated"].(bool)
	return ok && auth, nil
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := isAuthenticated(r)
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		if !authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func RequireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := isAuthenticated(r)
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		if !authenticated {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
