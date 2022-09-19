package auth

import (
	"errors"
)

type RoleID int32

type Role struct {
	ID   RoleID
	Name string
	//UserList map[UserID]struct{}
}

var (
	ErrRoleExists   = errors.New("role already exists")
	ErrRoleNotExist = errors.New("role does not exist")
)
