package auth

import (
	"errors"
	"time"
)

type TokenValue string

type Token struct {
	Value   TokenValue
	User    UserID
	Expires time.Time
}

var (
	ErrInvalidToken = errors.New("invalid auth token")
)
