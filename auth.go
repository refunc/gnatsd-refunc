package main

import (
	"encoding/json"
	"fmt"

	"github.com/antmanler/gnatsd-jwt/jwtauth"
	"github.com/garyburd/redigo/redis"
	"github.com/nats-io/gnatsd/server"
)

type customAuther interface {
	server.Authentication
	SetLogger(logger jwtauth.Logger)
}

type refuncAuth struct {
	pool        *redis.Pool
	tokenAuther customAuther
	logger      jwtauth.Logger
}

// credSyncer syncs and manages funcinsts.
type credSyncer struct {
}

// static assert
var _ server.Authentication = (*refuncAuth)(nil)

func (auth *refuncAuth) Check(c server.ClientAuthentication) bool {
	opts := c.GetOpts()
	if opts.Authorization != "" {
		if auth.tokenAuther == nil {
			return false
		}
		return auth.tokenAuther.Check(c)
	}
	if opts.Username == "" || opts.Password == "" {
		return false
	}
	user, err := auth.Get(opts.Username)
	if err != nil {
		auth.Errorf("Failed to get creds for %q, %v", opts.Username, err)
		return false
	}
	if user.Password != opts.Password {
		return false
	}
	c.RegisterUser(user)
	auth.Debugf("Register user %q with permissions %v", user.Username, user.Permissions != nil)
	return true
}

func (auth *refuncAuth) Get(key string) (*server.User, error) {
	c := auth.pool.Get()
	defer c.Close()

	reply, err := c.Do("GET", key)
	if err != nil {
		return nil, err
	}
	bts, ok := reply.([]byte)
	if !ok {
		return nil, fmt.Errorf("value for %q is not bytes", key)
	}

	var user struct {
		ID          string              `json:"id,omitempty"`
		AccessKey   string              `json:"accessKey,omitempty"`
		SecretKey   string              `json:"secretKey,omitempty"`
		Permissions *server.Permissions `json:"permissions"`
	}
	if err := json.Unmarshal(bts, &user); err != nil {
		return nil, err
	}
	if user.AccessKey != key {
		return nil, fmt.Errorf("key not match %q != %q", user.AccessKey, key)
	}
	natsUser := &server.User{
		Password:    user.SecretKey,
		Permissions: user.Permissions,
	}
	if user.ID != "" {
		natsUser.Username = user.ID
	} else {
		natsUser.Username = user.AccessKey
	}
	return natsUser, nil
}

// SetLogger set logger
func (auth *refuncAuth) SetLogger(logger jwtauth.Logger) {
	if auth.tokenAuther != nil {
		auth.tokenAuther.SetLogger(logger)
	}
	auth.logger = logger
}

// Errorf for error logs
func (auth *refuncAuth) Errorf(format string, v ...interface{}) {
	if auth.logger != nil {
		auth.logger.Errorf(format, v...)
	}
}

// Debugf for debug log
func (auth *refuncAuth) Debugf(format string, v ...interface{}) {
	if auth.logger != nil {
		auth.logger.Debugf(format, v...)
	}
}
