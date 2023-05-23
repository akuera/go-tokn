package jwt

import (
	"fmt"
	"github.com/akuera/go-tokn/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"time"
)

type tokenType string

var (
	Refresh tokenType = "refresh"
	Access  tokenType = "access"
)

func New(refreshSecret, accessSecret string, refreshTokenDuration, accessTokenDuration time.Duration) Tokenizer {
	if accessTokenDuration > refreshTokenDuration {
		return nil
	}
	return &tokenizer{
		refreshSecret:        refreshSecret,
		accessSecret:         accessSecret,
		refreshTokenDuration: refreshTokenDuration,
		accessTokenDuration:  accessTokenDuration,
	}
}

type tokenizer struct {
	refreshSecret        string
	accessSecret         string
	refreshTokenDuration time.Duration
	accessTokenDuration  time.Duration
}

type Tokenizer interface {
	Sign(fields map[string]interface{}, tokenType tokenType) (string, error)
	Verify(token string) bool
	RegenerateToken(token string) string
}

func (t *tokenizer) Sign(fields map[string]interface{}, tokenType tokenType) (string, error) {
	var expires time.Time
	secret := t.getSecret(tokenType)

	switch tokenType {
	case Refresh:
		expires = time.Now().Add(t.refreshTokenDuration)
	case Access:
		expires = time.Now().Add(t.accessTokenDuration)
	}

	claims := &models.Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expires.Unix(),
		},
	}
	if fields != nil {
		for k, v := range fields {
			claims.Set(k, v)
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func (t *tokenizer) Verify(token string) bool {
	claims, jwtToken := t.getJwtToken(token, Refresh)
	if jwtToken == nil {
		return false
	}
	decConfig := mapstructure.DecoderConfig{
		TagName: "json",
		Result:  &claims,
	}
	dec, err := mapstructure.NewDecoder(&decConfig)
	if err != nil {
		return false
	}
	err = dec.Decode(jwtToken.Claims)
	if err != nil {
		return false
	}
	return true
}

func (t *tokenizer) RegenerateToken(accessToken string) string {
	claims, _ := t.getJwtToken(accessToken, Access)
	if claims == nil {
		return ""
	}
	token, err := t.Sign(claims.Fields(), Access)
	if err != nil {
		return ""
	}
	return token
}

func (t *tokenizer) getJwtToken(token string, tokenType tokenType) (*models.Claims, *jwt.Token) {
	var claims *models.Claims
	var secret = t.getSecret(tokenType)
	tok, err := jwt.ParseWithClaims(token, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("error resolving token method")
		}
		claims = token.Claims.(*models.Claims)
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		return nil, nil
	}
	return claims, tok
}

func (t *tokenizer) getSecret(tokenType tokenType) string {
	var secret string

	switch tokenType {
	case Refresh:
		secret = t.refreshSecret
	case Access:
		secret = t.accessSecret
	}
	return secret
}
