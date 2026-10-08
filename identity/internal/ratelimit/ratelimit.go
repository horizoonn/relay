package ratelimit

type Scope string

const (
	EmailIP      Scope = "email-request-ip"
	EmailAccount Scope = "email-request-account"
	ActionIP     Scope = "account-action-ip"
	LoginIP      Scope = "login-ip"
	LoginAccount Scope = "login-account"
	RegisterIP   Scope = "register-ip"
	RefreshIP    Scope = "refresh-ip"
	ReadUser     Scope = "read-user"
	LogoutIP     Scope = "logout-ip"
	RevokeUser   Scope = "revoke-user"
)
