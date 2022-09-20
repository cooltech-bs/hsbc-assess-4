package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewInMemoryServer(t *testing.T) {
	var nilServer *InMemoryServer
	{
		svr, err := NewInMemoryServer(nil)
		assert.Equal(t, nilServer, svr, "should return nil if config is nil")
		assert.Equal(t, ErrInvalidConfig, err, "should give ErrInvalidConfig if config is nil")
	}
	{
		svr, err := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 59})
		assert.Equal(t, nilServer, svr, "should return nil if TokenExpireSec is too short")
		assert.Equal(t, ErrInvalidConfig, err, "should give ErrInvalidConfig if TokenExpireSec is too short")
	}
	{
		cfg := &InMemoryServerConfig{
			TokenExpireSec: 7200,
		}
		svr, err := NewInMemoryServer(cfg)
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, UserID(1), svr.nextUser, "IDs should start from 1")
		assert.Equal(t, RoleID(1), svr.nextRole, "IDs should start from 1")

		cfg.TokenExpireSec = 3600
		assert.Equal(t, int32(7200), svr.cfg.TokenExpireSec, "once initialized, config should not be externally changed")
	}
}

func TestCreateUser(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	{
		_, err := svr.CreateUser("dummy", "")
		assert.Equal(t, ErrWeakPassword, err, "should disallow empty password")
	}
	{
		id, err := svr.CreateUser("anna", "passw0rd")
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, &User{
			ID:     id,
			Name:   "anna",
			Secret: getPasswordHash("passw0rd"),
			Roles:  map[RoleID]*Role{},
		}, svr.GetUserByName("anna"), "should create the user anna")
	}
	{
		_, err := svr.CreateUser("anna", "passw1rd")
		assert.Equal(t, ErrUserExists, err, "should not create another user with the same name")
	}
	{
		id, err := svr.CreateUser("belle", "passw2rd")
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, UserID(2), id, "user ID should increment")
	}
}

func TestDeleteUser(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	id, _ := svr.CreateUser("phoebe", "weakpswd")
	{
		err := svr.DeleteUser(101)
		assert.Equal(t, ErrUserNotExist, err, "should give ErrUserNotExist if attempted to delete a nonexistent user")
	}
	{
		err := svr.DeleteUser(id)
		assert.Equal(t, nil, err, "should success")
	}
	{
		err := svr.DeleteUser(id)
		assert.Equal(t, ErrUserNotExist, err, "should not be able to repeatedly delete a user")
	}
}

func TestCreateRole(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	{
		id, err := svr.CreateRole("fuseblk")
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, &Role{
			ID:   id,
			Name: "fuseblk",
		}, svr.GetRoleByName("fuseblk"), "should create the role fuseblk")
	}
	{
		_, err := svr.CreateRole("fuseblk")
		assert.Equal(t, ErrRoleExists, err, "should not create another role with the same name")
	}
	{
		id, err := svr.CreateRole("plugdev")
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, RoleID(2), id, "role ID should increment")
	}
}

func TestDeleteRole(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	id, _ := svr.CreateRole("scanner")
	{
		err := svr.DeleteRole(101)
		assert.Equal(t, ErrRoleNotExist, err, "should give ErrRoleNotExist if attempted to delete a nonexistent group")
	}
	{
		err := svr.DeleteRole(id)
		assert.Equal(t, nil, err, "should success")
	}
	{
		err := svr.DeleteRole(id)
		assert.Equal(t, ErrRoleNotExist, err, "should not be able to repeatedly delete a role")
	}
}

func TestAddRoleToUser(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("phoebe", "weakpswd")
	rid, _ := svr.CreateRole("scanner")
	{
		err := svr.AddRoleToUser(uid, 101)
		assert.Equal(t, ErrRoleNotExist, err, "should give ErrRoleNotExist")
		err = svr.AddRoleToUser(101, rid)
		assert.Equal(t, ErrUserNotExist, err, "should give ErrUserNotExist")
	}
	{
		err := svr.AddRoleToUser(uid, rid)
		assert.Equal(t, nil, err, "should success")
		user := svr.GetUser(uid)
		assert.Equal(t, map[RoleID]*Role{
			1: {ID: 1, Name: "scanner"},
		}, user.Roles, "should have the scanner role")
	}
}

func TestAuthenticate(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("fred", "addtssnbzq")
	{
		_, err := svr.Authenticate("cara", "")
		assert.Equal(t, ErrInvalidAuth, err, "should fail if user not found")
	}
	{
		_, err := svr.Authenticate("fred", "whhhrqddjs")
		assert.Equal(t, ErrInvalidAuth, err, "should fail if password is wrong")
	}
	{
		token, err := svr.Authenticate("fred", "addtssnbzq")
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, 12, len(token), "should be a 64-bit base64 token")
		assert.Equal(t, uid, svr.tokens[token].User, "the token should map to user fred")

		assert.Equal(t, 1, len(svr.tokenQ), "should have 1 epoch")
		assert.Equal(t, int32(1), svr.tokenQ[0].ServerEpoch, "the server should be at epoch 1")
		assert.Equal(t, svr.tokens[token], svr.tokenQ[0].Tokens[0], "the token in the queue should match that in the map")
	}
}

func TestInvalidate(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("fred", "addtssnbzq")
	token, _ := svr.Authenticate("fred", "addtssnbzq")
	var nilToken *Token
	{
		assert.Equal(t, uid, svr.tokens[token].User, "the token should map to user fred")
		svr.Invalidate(token)
		assert.Equal(t, nilToken, svr.tokens[token], "the token should be invalidated")
	}
}

func TestCheckRole(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("elton", "123456")
	rid, _ := svr.CreateRole("scanner")
	rid2, _ := svr.CreateRole("plugdev")
	svr.AddRoleToUser(uid, rid)
	token, _ := svr.Authenticate("elton", "123456")
	{
		_, err := svr.CheckRole("invalid", rid)
		assert.Equal(t, ErrInvalidToken, err, "should verify the token")
	}
	{
		_, err := svr.CheckRole(token, 101)
		assert.Equal(t, ErrRoleNotExist, err, "should error on invalid role")
	}
	{
		ret, err := svr.CheckRole(token, rid)
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, true, ret, "should have the role scanner")
	}
	{
		ret, err := svr.CheckRole(token, rid2)
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, false, ret, "should not have the role plugdev")
	}
}

func TestAllRoles(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("elton", "123456")
	rid, _ := svr.CreateRole("scanner")
	rid2, _ := svr.CreateRole("plugdev")
	svr.AddRoleToUser(uid, rid)
	svr.AddRoleToUser(uid, rid2)
	token, _ := svr.Authenticate("elton", "123456")
	{
		_, err := svr.AllRoles("invalid")
		assert.Equal(t, ErrInvalidToken, err, "should verify the token")
	}
	{
		ret, err := svr.AllRoles(token)
		assert.Equal(t, nil, err, "should success")
		assert.Equal(t, 2, len(ret), "should have 2 roles")
	}
}

// TestVerifyToken includes cases not covered by TestCheckRole and TestAllRoles, such as removing expired tokens.
func TestVerifyToken(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 60})
	uid, _ := svr.CreateUser("elton", "123456")
	{
		token, _ := svr.Authenticate("elton", "123456")
		assert.Equal(t, 1, len(svr.tokens), "the server should have one token")
		svr.tokens[token].Expires = time.Now().Add(-30 * time.Second) // Manually modify token expiration time to the past
		_, err := svr.verifyToken(token)
		assert.Equal(t, ErrInvalidToken, err, "token should expire")
	}
	{
		token, _ := svr.Authenticate("elton", "123456")
		assert.Equal(t, 1, len(svr.tokens), "the server should have one token")
		svr.DeleteUser(uid)
		_, err := svr.verifyToken(token)
		assert.Equal(t, ErrInvalidToken, err, "token should be invalidated after user removal")
		assert.Equal(t, 0, len(svr.tokens), "the server should remove the token")
	}
}

func TestPruneTokens(t *testing.T) {
	svr, _ := NewInMemoryServer(&InMemoryServerConfig{TokenExpireSec: 1800})
	svr.CreateUser("elton", "123456")
	{
		svr.Authenticate("elton", "123456")
		svr.Authenticate("elton", "123456")
		svr.Authenticate("elton", "123456")
		assert.Equal(t, 3, len(svr.tokens), "the server should create one token per authentication")

		svr.startedOn = time.Now().Add(-121 * time.Minute) // Two hours passed magically
		svr.Authenticate("elton", "123456")
		assert.Equal(t, 1, len(svr.tokens), "the server should remove stale tokens")
	}
}
