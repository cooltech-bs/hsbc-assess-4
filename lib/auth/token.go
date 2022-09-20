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

type TokenQueue struct {
	ServerEpoch int32
	Tokens      []*Token
}

var (
	ErrInvalidToken = errors.New("invalid auth token")
)
