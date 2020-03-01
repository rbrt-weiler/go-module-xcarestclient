package xcarestclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type TokenRequest struct {
	GrantType string `json:"grantType"`
	UserID    string `json:"userId"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}

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

func (t *OAuthToken) Decode() error {
	tokenFields := strings.Split(t.AccessToken, ".")

	if tokenHeader, thErr := base64.RawURLEncoding.DecodeString(tokenFields[0]); thErr != nil {
		return fmt.Errorf("could not base64 decode token header: %s", thErr)
	} else {
		if headerErr := json.Unmarshal(tokenHeader, &t.TokenHeader); headerErr != nil {
			return fmt.Errorf("could not decode token header: %s", headerErr)
		}
	}

	if tokenPayload, tpErr := base64.RawURLEncoding.DecodeString(tokenFields[1]); tpErr != nil {
		return fmt.Errorf("could not base64 decode token payload: %s", tpErr)
	} else {
		if payloadErr := json.Unmarshal(tokenPayload, &t.TokenPayload); payloadErr != nil {
			return fmt.Errorf("could not decode token payload: %s", payloadErr)
		}
		t.TokenPayload.ExpiresAt = time.Unix(t.TokenPayload.ExpiresAtUnixfmt, 0)
	}

	if tokenSignature, tsErr := base64.RawURLEncoding.DecodeString(tokenFields[2]); tsErr != nil {
		return fmt.Errorf("could not base64 decode token signature: %s", tsErr)
	} else {
		t.TokenSignature = tokenSignature
	}

	return nil
}
