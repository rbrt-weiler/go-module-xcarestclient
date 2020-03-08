package xcarestclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenRequest is the data structure required for authentication against XCA.
type TokenRequest struct {
	GrantType string `json:"grantType"`
	UserID    string `json:"userId"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}

// OAuthToken stores a plain access token along with its decoded fields.
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IdleTimeout  int    `json:"idle_timeout"`
	RefreshToken string `json:"refresh_token"`
	AdminRole    string `json:"adminRole"`
	TokenHeader  struct {
		KID      string `json:"kid"`
		Type     string `json:"typ"`
		Algorith string `json:"alg"`
	}
	TokenPayload struct {
		JWTID            string    `json:"jti"`
		Subject          string    `json:"sub"`
		Issuer           string    `json:"iss"`
		ExtremeRole      string    `json:"extreme_role"`
		ExpiresAt        time.Time `json:"-"`
		ExpiresAtUnixfmt int64     `json:"exp"`
	}
	TokenSignature []byte
}

// Decode decodes a raw OAuth token into the OAuthToken structure.
func (t *OAuthToken) Decode() error {
	var data []byte
	var err error

	tokenFields := strings.Split(t.AccessToken, ".")

	// Header
	if data, err = base64.RawURLEncoding.DecodeString(tokenFields[0]); err != nil {
		return fmt.Errorf("could not base64 decode token header: %s", err)
	}
	if err = json.Unmarshal(data, &t.TokenHeader); err != nil {
		return fmt.Errorf("could not decode token header: %s", err)
	}

	// Payload
	if data, err = base64.RawURLEncoding.DecodeString(tokenFields[1]); err != nil {
		return fmt.Errorf("could not base64 decode token payload: %s", err)
	}
	if err = json.Unmarshal(data, &t.TokenPayload); err != nil {
		return fmt.Errorf("could not decode token payload: %s", err)
	}
	t.TokenPayload.ExpiresAt = time.Unix(t.TokenPayload.ExpiresAtUnixfmt, 0)

	// Signature
	if data, err = base64.RawURLEncoding.DecodeString(tokenFields[2]); err != nil {
		return fmt.Errorf("could not base64 decode token signature: %s", err)
	}
	t.TokenSignature = data

	return nil
}
