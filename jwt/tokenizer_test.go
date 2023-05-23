package jwt_test

import (
	"github.com/akuera/go-tokn/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name                string
		accessTokenTimeout  time.Duration
		refreshTokenTimeout time.Duration
		wantNil             bool
	}{
		{
			name:                "Success",
			accessTokenTimeout:  5 * time.Second,
			refreshTokenTimeout: 10 * time.Second,
			wantNil:             false,
		},
		{
			name:                "Fail",
			accessTokenTimeout:  15 * time.Second,
			refreshTokenTimeout: 10 * time.Second,
			wantNil:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := jwt.New("refresh", "access", tt.refreshTokenTimeout, tt.accessTokenTimeout)
			assert.Equal(t, tt.wantNil, tok == nil)
		})
	}
}

func TestTokenizer_Verify(t *testing.T) {
	tok := jwt.New("refresh", "access", 30*time.Second, 20*time.Second)
	assert.NotNil(t, tok)
	tok2 := jwt.New("refresh2", "access2", 30*time.Second, 20*time.Second)
	assert.NotNil(t, tok2)
	token, err := tok.Sign(map[string]interface{}{"user": "testUser"}, jwt.Refresh)
	assert.NoError(t, err)
	token2, err := tok2.Sign(nil, jwt.Refresh)
	assert.NoError(t, err)
	tests := []struct {
		name      string
		token     string
		tokenizer jwt.Tokenizer
		want      bool
	}{
		{
			name:      "invalid signature",
			token:     token2,
			tokenizer: tok,
			want:      false,
		},
		{
			name:      "success",
			token:     token,
			tokenizer: tok,
			want:      true,
		},
		{
			name:      "invalid token",
			token:     "invalid token",
			tokenizer: tok,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.tokenizer.Verify(tt.token)
			assert.Equal(t, tt.want, valid)
		})
	}
}

func TestTokenizer_RegenerateToken(t *testing.T) {
	tok := jwt.New("refresh", "access", 30*time.Minute, 20*time.Minute)
	assert.NotNil(t, tok)
	token, err := tok.Sign(map[string]interface{}{"user": "testUser"}, jwt.Access)
	assert.NoError(t, err)

	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{
			name:  "success",
			token: token,
			valid: true,
		},
		{
			name:  "invalid signature",
			token: "invalid token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tok.RegenerateToken(tt.token)
			assert.Equal(t, tt.valid, token != "")
		})
	}
}

func TestTokenizer_Sign(t *testing.T) {
	tok := jwt.New("refresh", "access", 30*time.Minute, 20*time.Minute)
	assert.NotNil(t, tok)
	tests := []struct {
		name   string
		fields map[string]interface{}
	}{
		{
			name: "with fields",
			fields: map[string]interface{}{
				"field1": "value1",
			},
		},
		{
			name:   "nil fields",
			fields: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tok.Sign(tt.fields, jwt.Access)
			assert.NoError(t, err)
		})
	}
}
