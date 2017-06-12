package goagooglelogin

import (
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

func NewJWTMiddleware(conf *GoaGloginConf, newJWTSecurity *goa.JWTSecurity) goa.Middleware {
	if conf != nil {
		conf = &DefaultGoaGloginConf
	}
	return jwt.New(conf.LoginSigned, nil, newJWTSecurity)
}
