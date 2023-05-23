package models

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	Field map[string]interface{} `json:"field"`
	jwt.StandardClaims
}

func (c *Claims) Set(key string, value interface{}) {
	if c.Field == nil {
		c.Field = make(map[string]interface{})
	}
	c.Field[key] = value
}

func (c *Claims) Get(key string) interface{} {
	if c.Field == nil {
		return nil
	}
	return c.Field[key]
}

func (c *Claims) Fields() map[string]interface{} {
	return c.Field
}
