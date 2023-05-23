package models_test

import (
	"github.com/akuera/go-tokn/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClaims_Set(t *testing.T) {
	tests := []struct {
		name  string
		field func() (string, interface{})
		want  map[string]interface{}
	}{
		{
			name: "multiple field",
			want: map[string]interface{}{
				"foo": "bar",
			},
			field: func() (string, interface{}) {
				return "foo", "bar"
			},
		},
		{
			name: "no field",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &models.Claims{}
			if tt.field != nil {
				claims.Set(tt.field())
			}
			assert.Equal(t, tt.want, claims.Fields())
		})
	}
}

func TestClaims_Get(t *testing.T) {
	tests := []struct {
		name   string
		claims *models.Claims
		key    string
		want   interface{}
	}{
		{
			name: "success",
			claims: &models.Claims{Field: map[string]interface{}{
				"foo": "bar",
			}},
			key:  "foo",
			want: "bar",
		},
		{
			name: "no field",
			claims: &models.Claims{Field: map[string]interface{}{
				"foo": "bar",
			}},
			key:  "ping",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := tt.claims.Get(tt.key)
			assert.Equal(t, tt.want, val)
		})
	}
}

func TestClaims_Fields(t *testing.T) {
	tests := []struct {
		name   string
		claims *models.Claims
		want   map[string]interface{}
	}{
		{
			name: "has value",
			claims: &models.Claims{Field: map[string]interface{}{
				"foo": "bar",
			}},
			want: map[string]interface{}{
				"foo": "bar",
			},
		},
		{
			name:   "empty map",
			claims: &models.Claims{Field: map[string]interface{}{}},
			want:   map[string]interface{}{},
		},
		{
			name:   "nil map",
			claims: &models.Claims{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := tt.claims.Fields()
			assert.Equal(t, tt.want, fields)
		})
	}
}
