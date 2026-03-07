package session

import (
	"errors"
	"log"
	"net/http"

	"GoResolver/internal/config"
	"github.com/gorilla/sessions"
)

var (
	ErrStoreNotInitialized = errors.New("session store not initialized")
	Store                  *sessions.CookieStore
)

func Init() error {
	currentSecret, err := config.RequiredSecret("GORESOLVER_SESSION_SECRET")
	if err != nil {
		return err
	}

	currentAuthKey, err := config.DeriveKey(currentSecret, "goresolver-session-auth", 32)
	if err != nil {
		return err
	}
	currentBlockKey, err := config.DeriveKey(currentSecret, "goresolver-session-block", 32)
	if err != nil {
		return err
	}

	keyPairs := [][]byte{currentAuthKey, currentBlockKey}

	previousSecret, ok, err := config.OptionalSecret("GORESOLVER_SESSION_SECRET_PREVIOUS")
	if err != nil {
		return err
	}
	if ok {
		previousAuthKey, err := config.DeriveKey(previousSecret, "goresolver-session-auth", 32)
		if err != nil {
			return err
		}
		previousBlockKey, err := config.DeriveKey(previousSecret, "goresolver-session-block", 32)
		if err != nil {
			return err
		}
		keyPairs = append(keyPairs, previousAuthKey, previousBlockKey)
	}

	Store = sessions.NewCookieStore(keyPairs...)
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   config.Bool("GORESOLVER_SESSION_SECURE", true),
		SameSite: http.SameSiteLaxMode,
	}
	return nil
}

func Get(r *http.Request, name string) (*sessions.Session, error) {
	if Store == nil {
		return nil, ErrStoreNotInitialized
	}

	sess, err := Store.Get(r, name)
	if err == nil {
		return sess, nil
	}

	log.Printf("session %q decode failed, starting fresh session: %v", name, err)

	fresh := sessions.NewSession(Store, name)
	if Store.Options != nil {
		opts := *Store.Options
		fresh.Options = &opts
	}
	fresh.IsNew = true
	return fresh, nil
}
