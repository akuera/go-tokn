package models

type TokenStore interface {
	Store(tokenID, refreshToken, accessToken string) error
	Retrieve(refreshToken string) (accessToken string)
	Destroy(refreshToken string) error
}
