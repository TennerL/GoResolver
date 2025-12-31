package services

import (
	"GoResolver/internal/db"
	"golang.org/x/crypto/bcrypt"
)

type LoginService struct {}

func NewLoginService() *LoginService {
	return &LoginService{}
}

// AuthResult holds login attempt result
type AuthResult struct {
	Success bool
	Error   string
	UserID  int
}

// Authenticate checks username/password
func (s *LoginService) Authenticate(username, password string) AuthResult {
	var id int
	var hash string

	row := db.DB.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username)
	err := row.Scan(&id, &hash)
	if err != nil {
		return AuthResult{Success: false, Error: "invalid credentials"}
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return AuthResult{Success: false, Error: "invalid credentials"}
	}

	return AuthResult{Success: true, UserID: id}
}

// Optional: some data for template rendering
func (s *LoginService) GetAuth() interface{} {
	// return any info your template needs; can be empty for now
	return nil
}
