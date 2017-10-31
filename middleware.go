package goagooglelogin

import (
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

// NewJWTMiddleware is middlewar
func NewJWTMiddleware(conf *GoaGloginConf, newJWTSecurity *goa.JWTSecurity) goa.Middleware {
	if conf == nil {
		conf = &DefaultGoaGloginConf
	}
	keys := []jwt.Key{conf.LoginSigned}
	return jwt.New(jwt.NewSimpleResolver(keys), nil, newJWTSecurity)
}
