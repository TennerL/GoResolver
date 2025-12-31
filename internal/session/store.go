package session

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var Store = sessions.NewCookieStore([]byte("super-secret-key"))

func init() {
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, 
		HttpOnly: true,
		Secure:   true,                
		SameSite: http.SameSiteLaxMode, 
	}
}
