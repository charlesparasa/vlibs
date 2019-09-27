package server


type APIContext struct {
	Tenant         string // Tenant Name for identification of Tenant
	UserName       string // Username against the token
	ClientID       string // ClientID for the clients ID
	Token          string // Token is the api token
	RequestID      string // RequestID - used to track logs across a request-response cycle
	CorrelationID  string // CorrelationID - used to track logs across a user's session
}

type ctxType string

const (
	// APICtx - defining a separate type to avoid colliding with basic type
	APICtx ctxType = "apiCtx"
)