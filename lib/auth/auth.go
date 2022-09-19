package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

type InMemoryServerConfig struct {
	TokenExpireSec int32
	PruneInterval  int32
}

type InMemoryServer struct {
	cfg InMemoryServerConfig

	users  map[UserID]*User
	uname  map[string]*User
	roles  map[RoleID]*Role
	rname  map[string]*Role
	tokens map[TokenValue]*Token

	nextUser UserID
	nextRole RoleID

	tokenQueue []*Token // for pruning expired tokens
}

var (
	ErrInternal = errors.New("internal server error")
)

func (s *InMemoryServer) CreateUser(name, password string) (UserID, error) {
	if _, exists := s.uname[name]; exists {
		return 0, ErrUserExists
	}

	newUser := User{
		ID:     s.nextUser,
		Name:   name,
		Secret: getPasswordHash(password),
	}
	s.users[s.nextUser] = &newUser
	s.uname[name] = &newUser
	s.nextUser++
	return newUser.ID, nil
}

func (s *InMemoryServer) DeleteUser(user UserID) error {
	userObj, ok := s.users[user]
	if !ok {
		return ErrUserNotExist
	}

	delete(s.users, user)
	delete(s.uname, userObj.Name)
	return nil
}

func (s *InMemoryServer) CreateRole(name string) (RoleID, error) {
	if _, exists := s.rname[name]; exists {
		return 0, ErrRoleExists
	}

	newRole := Role{
		ID:   s.nextRole,
		Name: name,
	}
	s.roles[s.nextRole] = &newRole
	s.rname[name] = &newRole
	s.nextRole++
	return newRole.ID, nil
}

func (s *InMemoryServer) DeleteRole(role RoleID) error {
	roleObj, ok := s.roles[role]
	if !ok {
		return ErrRoleNotExist
	}

	delete(s.roles, role)
	delete(s.rname, roleObj.Name)
	return nil
}

func (s *InMemoryServer) AddRoleToUser(user UserID, role RoleID) error {
	userObj, ok := s.users[user]
	if !ok {
		return ErrUserNotExist
	}
	roleObj, ok := s.roles[role]
	if !ok {
		return ErrRoleNotExist
	}

	userObj.Roles[roleObj.ID] = roleObj
	return nil
}

func (s *InMemoryServer) Authenticate(username, password string) (TokenValue, error) {
	userObj, ok := s.uname[username]
	if !ok {
		return "", ErrInvalidAuth
	}
	secret := getPasswordHash(password)
	if !bytes.Equal(secret, userObj.Secret) {
		return "", ErrInvalidAuth
	}

	token, err := s.newToken(userObj)
	if err != nil {
		return "", ErrInternal
	}
	s.tokens[token.Value] = token
	return token.Value, nil
}

func (s *InMemoryServer) Invalidate(token TokenValue) {
	delete(s.tokens, token)
}

func (s *InMemoryServer) CheckRole(token TokenValue, role RoleID) (bool, error) {
	userObj, err := s.verifyToken(token)
	if err != nil {
		return false, err
	}
	_, belongs := userObj.Roles[role]
	return belongs, nil
}

func (s *InMemoryServer) AllRoles(token TokenValue) ([]RoleID, error) {
	userObj, err := s.verifyToken(token)
	if err != nil {
		return nil, err
	}
	roleList := make([]RoleID, len(userObj.Roles))
	var i int
	for role := range userObj.Roles {
		roleList[i] = role
		i++
	}
	return roleList, nil
}

// *-* Internal *-*

func (s *InMemoryServer) newToken(u *User) (*Token, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	t := time.Now()
	return &Token{
		Value:   TokenValue(base64.StdEncoding.EncodeToString(b)),
		User:    u.ID,
		Expires: t.Add(time.Duration(s.cfg.PruneInterval) * time.Second),
	}, nil
}

func (s *InMemoryServer) verifyToken(t TokenValue) (*User, error) {
	tokenObj, ok := s.tokens[t]
	if !ok {
		return nil, ErrInvalidToken
	}
	now := time.Now()
	if now.After(tokenObj.Expires) {
		// Lazily remove expired tokens
		delete(s.tokens, t)
		return nil, ErrInvalidToken
	}
	userObj, ok := s.users[tokenObj.User]
	if !ok {
		// Lazily invalidate tokens after the user is deleted
		delete(s.tokens, t)
		return nil, ErrInvalidToken
	}
	return userObj, nil
}
