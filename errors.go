package go_tokn

type err string

var (
	ErrRegenerateFailed    = err("failed to regenerate token")
	ErrTokenExpired        = err("token is expired")
	ErrTokenInvalid        = err("token is invalid")
	ErrRefreshTokenMissing = err("refresh token missing")
)

func (e err) Error() string {
	return string(e)
}
