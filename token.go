package go_tokn

import (
	"github.com/akuera/go-tokn/jwt"
	"github.com/akuera/go-tokn/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type token struct {
	store         models.TokenStore
	tokenizer     jwt.Tokenizer
	refreshSecret string
	accessSecret  string
}

type TokenInt interface {
	CreateTokenPair(customFields map[string]interface{}) (*models.Token, error)
	ValidateToken(refreshToken string) error
	RefreshToken(refreshToken string) (*models.Token, error)
}

func (t *token) CreateTokenPair(customFields map[string]interface{}) (*models.Token, error) {
	refreshTokenExp := 12 * time.Hour
	expiresAt := time.Now().Add(refreshTokenExp).Unix()
	tokenID := primitive.NewObjectIDFromTimestamp(time.Now()).Hex()
	refreshToken, err := t.tokenizer.Sign(nil, jwt.Refresh)
	if err != nil {
		return nil, err
	}
	accessToken, err := t.tokenizer.Sign(customFields, jwt.Access)
	if err != nil {
		return nil, err
	}
	err = t.store.Store(tokenID, refreshToken, accessToken)
	if err != nil {
		return nil, err
	}
	return &models.Token{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (t *token) ValidateToken(refreshToken string) error {
	valid := t.tokenizer.Verify(refreshToken)
	if !valid {
		return ErrTokenInvalid
	}
	accessToken := t.store.Retrieve(refreshToken)
	if len(accessToken) == 0 {
		return ErrRefreshTokenMissing
	}
	return nil
}

func (t *token) RefreshToken(refreshToken string) (*models.Token, error) {
	valid := t.tokenizer.Verify(refreshToken)
	if !valid {
		return nil, ErrTokenInvalid
	}
	accessToken := t.store.Retrieve(refreshToken)
	if len(accessToken) == 0 {
		return nil, ErrRefreshTokenMissing
	}
	accessToken = t.tokenizer.RegenerateToken(accessToken)
	if len(accessToken) == 0 {
		return nil, ErrRegenerateFailed
	}
	err := t.store.Destroy(refreshToken)
	if err != nil {
		return nil, err
	}
	refreshToken, err = t.tokenizer.Sign(nil, jwt.Refresh)
	if err != nil {
		return nil, err
	}
	refreshTokenExp := 12 * time.Hour
	expiresAt := time.Now().Add(refreshTokenExp).Unix()
	return &models.Token{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func New(store models.TokenStore, refreshSecret, accessSecret string, refreshTokenDuration, accessTokenDuration time.Duration) TokenInt {
	return &token{
		store:         store,
		tokenizer:     jwt.New(refreshSecret, accessSecret, refreshTokenDuration, accessTokenDuration),
		refreshSecret: refreshSecret,
		accessSecret:  accessSecret,
	}
}
