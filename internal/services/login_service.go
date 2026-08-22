package services

import (
	"GoResolver/internal/db"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	loginCooldown        = time.Minute
	loginIPMaxFailures   = 3
	loginUserMaxFailures = 5
	loginBlockDuration   = 24 * time.Hour
)

type loginAttemptState struct {
	Failures     int
	NextTry      time.Time
	BlockedUntil time.Time
}

type LoginService struct {
	mu     sync.Mutex
	byIP   map[string]loginAttemptState
	byUser map[string]loginAttemptState
	notify func(username, ip string, attemptedAt time.Time, reason string, ipFailures, userFailures int, blockedUntil time.Time) error
}

func NewLoginService() *LoginService {
	return &LoginService{byIP: make(map[string]loginAttemptState), byUser: make(map[string]loginAttemptState), notify: sendLoginFailureMail}
}

// AuthResult holds login attempt result
type AuthResult struct {
	Success bool
	Error   string
	UserID  int
}

// Authenticate checks username/password
func (s *LoginService) Authenticate(username, password, ip string) AuthResult {
	username = strings.TrimSpace(username)
	ip = strings.TrimSpace(ip)
	now := time.Now()
	if wait := s.loginWait(username, ip, now); wait > 0 {
		s.recordLoginFailure(username, ip, now, "attempt during cooldown or lock")
		wait = s.loginWait(username, ip, now)
		return AuthResult{Success: false, Error: fmt.Sprintf("login temporarily locked; retry in %s", wait.Round(time.Second))}
	}

	var id int
	var hash string

	row := db.DB.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username)
	err := row.Scan(&id, &hash)
	if err != nil {
		s.recordLoginFailure(username, ip, now, "unknown user")
		return AuthResult{Success: false, Error: "invalid credentials"}
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		s.recordLoginFailure(username, ip, now, "invalid password")
		return AuthResult{Success: false, Error: "invalid credentials"}
	}

	s.mu.Lock()
	delete(s.byIP, ip)
	delete(s.byUser, strings.ToLower(username))
	s.mu.Unlock()

	return AuthResult{Success: true, UserID: id}
}

func (s *LoginService) loginWait(username, ip string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var until time.Time
	states := []loginAttemptState{s.byUser[strings.ToLower(username)]}
	if loginIPCanBeBlocked(ip) {
		states = append(states, s.byIP[ip])
	}
	for _, state := range states {
		candidate := state.NextTry
		if state.BlockedUntil.After(candidate) {
			candidate = state.BlockedUntil
		}
		if candidate.After(until) {
			until = candidate
		}
	}
	if until.After(now) {
		return until.Sub(now)
	}
	return 0
}

func (s *LoginService) recordLoginFailure(username, ip string, now time.Time, reason string) {
	s.mu.Lock()
	ipState := loginAttemptState{}
	if loginIPCanBeBlocked(ip) {
		ipState = s.byIP[ip]
		ipState.Failures++
		ipState.NextTry = now.Add(loginCooldown)
		if ipState.Failures >= loginIPMaxFailures {
			ipState.BlockedUntil = now.Add(loginBlockDuration)
		}
		s.byIP[ip] = ipState
	}
	userKey := strings.ToLower(username)
	userState := s.byUser[userKey]
	userState.Failures++
	userState.NextTry = now.Add(loginCooldown)
	if userState.Failures >= loginUserMaxFailures {
		userState.BlockedUntil = now.Add(loginBlockDuration)
	}
	s.byUser[userKey] = userState
	s.mu.Unlock()

	if s.notify != nil {
		notify := s.notify
		go func() {
			if err := notify(username, ip, now, reason, ipState.Failures, userState.Failures, ipState.BlockedUntil); err != nil {
				log.Printf("login failure notification failed: %v", err)
			}
		}()
	}
}

func loginIPCanBeBlocked(raw string) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(raw), "[]"))
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}

// Optional: some data for template rendering
func (s *LoginService) GetAuth() interface{} {
	// return any info your template needs; can be empty for now
	return nil
}
