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
}

// InMemoryServer is an auth server that stores all its data in memory (without persistence).
// It uses maps to provide quick access with both IDs and names as key.
// TODO: use a mutex to protect internal data structures when operating multi-threaded.
type InMemoryServer struct {
	cfg InMemoryServerConfig

	users  map[UserID]*User
	uname  map[string]*User
	roles  map[RoleID]*Role
	rname  map[string]*Role
	tokens map[TokenValue]*Token

	// Auto-increment numerical IDs
	nextUser UserID
	nextRole RoleID

	// For removing expired tokens
	tokenQ []TokenQueue

	// For calculating server epoch
	startedOn time.Time
}

var (
	ErrInvalidConfig = errors.New("wrong config")
	ErrInternal      = errors.New("internal server error")
)

// NewInMemoryServer creates an InMemoryServer for authentication and authorization.
// We assume that tokens must be valid for at least 1 minute to be useful. Setting TokenExpireSec
// to anything below that will result in an error.
//
// Returns: pointer to the new server instance
// Errors: ErrInvalidConfig
// TODO: allow setting nextUser and nextRole in config.
func NewInMemoryServer(config *InMemoryServerConfig) (*InMemoryServer, error) {
	if config == nil || config.TokenExpireSec < 60 {
		return nil, ErrInvalidConfig
	}

	svr := InMemoryServer{
		cfg:      *config,
		users:    make(map[UserID]*User),
		uname:    make(map[string]*User),
		roles:    make(map[RoleID]*Role),
		rname:    make(map[string]*Role),
		tokens:   make(map[TokenValue]*Token),
		nextUser: 1,
		nextRole: 1,
	}
	return &svr, nil
}

// *-* Public API *-*

// CreateUser adds a new user with given credentials.
//
// Returns: the ID of the new user
// Errors: ErrUserExists
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

// DeleteUser removes a user with given ID.
//
// Returns: none
// Errors: ErrUserNotExist
func (s *InMemoryServer) DeleteUser(user UserID) error {
	userObj, ok := s.users[user]
	if !ok {
		return ErrUserNotExist
	}

	delete(s.users, user)
	delete(s.uname, userObj.Name)
	return nil
}

// CreateRole adds a new role with given name.
//
// Returns: the ID of the new group
// Errors: ErrRoleExists
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

// DeleteRole removes a role with given ID.
//
// Returns: none
// Errors: ErrRoleNotExist
func (s *InMemoryServer) DeleteRole(role RoleID) error {
	roleObj, ok := s.roles[role]
	if !ok {
		return ErrRoleNotExist
	}

	delete(s.roles, role)
	delete(s.rname, roleObj.Name)
	return nil
}

// AddRoleToUser assigns a role to a user.
// It is a no-op if the user already has the role.
//
// Returns: none
// Errors: ErrUserNotExist, ErrRoleNotExist
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

// Authenticate checks a username/password pair, and creates a token for the user if it passes.
// Note that the password is clear text, like that in HTTP Basic auth.
// For security, the function does not distinguish "wrong username" from "wrong password".
// ErrInternal is returned only in rare cases where the system cannot provide enough randomness.
//
// Returns: the token string
// Errors: ErrInvalidAuth, ErrInternal
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

// Invalidate invalidates a token immediately.
//
// Returns: none
func (s *InMemoryServer) Invalidate(token TokenValue) {
	delete(s.tokens, token)
}

// CheckRole checks if the user identified by the token has the given role.
//
// Returns: true or false
// Errors: ErrInvalidToken
func (s *InMemoryServer) CheckRole(token TokenValue, role RoleID) (bool, error) {
	userObj, err := s.verifyToken(token)
	if err != nil {
		return false, err
	}
	_, belongs := userObj.Roles[role]
	return belongs, nil
}

// AllRoles return all role IDs associated with the user identified by the token.
//
// Returns: a list of RoleIDs (32-bit integers)
// Errors: ErrInvalidToken
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

// *-* Query operations *-*
// These functions provide mapping between IDs and names.
// nil is returned if the query has no result.
// The function names are self-explanatory.

func (s *InMemoryServer) GetUser(id UserID) *User {
	return s.users[id]
}

func (s *InMemoryServer) GetUserByName(name string) *User {
	return s.uname[name]
}

func (s *InMemoryServer) GetRole(id RoleID) *Role {
	return s.roles[id]
}

func (s *InMemoryServer) GetRoleByName(name string) *Role {
	return s.rname[name]
}

// *-* Internal *-*
// Bookkeeping, including token maintenance.

// newToken creates a new token for a user.
// It optionally triggers garbage collection for expired tokens.
func (s *InMemoryServer) newToken(u *User) (*Token, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	t := Token{
		Value:   TokenValue(base64.StdEncoding.EncodeToString(b)),
		User:    u.ID,
		Expires: now.Add(time.Duration(s.cfg.TokenExpireSec) * time.Second),
	}
	s.addToTokenQueue(&t)
	return &t, nil
}

// verifyToken ensures the token, as well as its associated user, is valid and not expired/deleted.
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

// pruneTokens remove expired tokens from memory.
// It is triggered roughly once per hour. TODO: support configuring this interval
func (s *InMemoryServer) pruneTokens() {
	var (
		i      int
		ep     = s.currentEpochInHour()
		expire = s.cfg.TokenExpireSec/3600 + 1
	)
	for i = 0; i < len(s.tokenQ); i++ {
		if ep-s.tokenQ[i].ServerEpoch <= expire {
			break
		}
		for _, token := range s.tokenQ[i].Tokens {
			delete(s.tokens, token.Value)
		}
	}
	// Avoid slice leak
	tmpTokenQueue := make([]TokenQueue, len(s.tokenQ)-i)
	copy(tmpTokenQueue, s.tokenQ[i:])
	s.tokenQ = tmpTokenQueue
}

// addToTokenQueue saves a reference to a token for later pruning.
func (s *InMemoryServer) addToTokenQueue(t *Token) {
	ep := s.currentEpochInHour()
	if l := len(s.tokenQ); l == 0 || s.tokenQ[l-1].ServerEpoch < ep {
		s.tokenQ = append(s.tokenQ, TokenQueue{
			ServerEpoch: ep,
		})
		s.pruneTokens()
	}
	l := len(s.tokenQ)
	s.tokenQ[l-1].Tokens = append(s.tokenQ[l-1].Tokens, t)
}

// currentEpochInHour gets the number of hours, starting from 1, since the server started.
func (s *InMemoryServer) currentEpochInHour() int32 {
	now := time.Now()
	elapsed := now.Sub(s.startedOn)
	return int32(elapsed.Seconds()+1) / 3600
}
