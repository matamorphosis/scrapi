package structs

import (
	"database/sql"
	"embed"
	"net/http"

	"github.com/golang-jwt/jwt"
)

type PublicDocuments struct {
	Swagger struct {
		Spec               []byte
		EmbeddedFileSystem embed.FS
	}
}

type HTTPRequestInfo struct {
	Method    string `json:"method"`
	URI       string `json:"uri"`
	Referer   string `json:"referer"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Time      string `json:"time"`
}

type URIPathVariable struct {
	VariableName string
	VarPrefix    string
}

type URIPath struct {
	Variables []*URIPathVariable
	URISuffix string
	Next      http.HandlerFunc
	Methods   []string
}

type UserDetails struct {
	User_ID      int
	Username     string
	PasswordHash string
	FirstName    string
	LastName     string
	MFA          string
	Role         string
	Token        sql.NullString
	TokenExp     sql.NullInt64
	Team_ID      int
}

type Claims struct {
	User_ID  int    `json:"user_id"`
	Username string `json:"username"`
	*jwt.StandardClaims
}

// swagger:parameters AuthRequest
type AuthRequest struct {
	// Authentication request body (Note for Dev Environment: The password field can be substituted with the passhash field. The value of this field is the password hash of the user, which can be used in the event a password is forgotten, to avoid the hassle of rotating keys.) MFA tokens are 4 digits in length.
	// In: body
	Body struct {
		// name: username
		// type: string
		// required: true
		Username string `json:"username"`
		// name: password
		// type: string
		// required: true
		Password     string `json:"password"`
		PasswordHash string `json:"passhash"`
		// name: mfa
		// type: string
		// required: true
		MFA string `json:"mfa"`
	}
}

// Authentication response
// swagger:response AuthResponse
type AuthResponse struct {
	// In: body
	Body struct {
		// JWT Token
		// type: string
		Token string `json:"token"`
		// Message
		// type: string
		Message string `json:"message"`
		// Flag		// type: string
		Flag string `json:"flag"`
	}
}

// Common error message
// swagger:response CommonMessage
type CommonMessage struct {
	// Error response message
	// In: body
	Body struct {
		// Error message
		// type: string
		Message string `json:"message"`
	}
}
