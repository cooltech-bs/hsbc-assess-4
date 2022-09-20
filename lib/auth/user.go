package auth

import (
	"crypto/sha256"
	"errors"
)

type UserID int64

type User struct {
	ID     UserID
	Name   string
	Secret []byte // password hash, default SHA-256
	Roles  map[RoleID]*Role
}

var (
	ErrWeakPassword = errors.New("password does not match requirements")
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotExist = errors.New("user does not exist")
	ErrInvalidAuth  = errors.New("authentication failed")
)

func getPasswordHash(pass string) []byte {
	arr := sha256.Sum256([]byte(pass))
	return arr[:]
}
