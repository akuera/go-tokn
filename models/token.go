package models

type Token struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token"`
	AccessToken  string `json:"access_token" bson:"access_token"`
	ExpiresAt    int64  `json:"expires_at" bson:"expiresAt"` // RefreshToken expiry
}
