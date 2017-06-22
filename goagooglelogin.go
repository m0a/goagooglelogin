package goagooglelogin

import (
	"context"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"google.golang.org/api/oauth2/v2"
)

type (
	// GoaGloginConf middleware config
	GoaGloginConf struct {
		LoginURL           string // defualt: /login
		CallbackURL        string // default: /oauth2callback
		StateSigned        string // state JWT key
		LoginSigned        string // login JWT key
		GoogleClientID     string
		GoogleClientSecret string
		CreateClaims       func(googleUserID string, userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo) (jwt.Claims, error)
		ExtensionIDs       []string
	}
)

var (
	// DefaultGoaGloginConf is the default googlelogin middleware config.
	DefaultGoaGloginConf = GoaGloginConf{
		LoginURL:           "/login",
		CallbackURL:        "/oauth2callback",
		StateSigned:        "f23oj3242jkl",
		LoginSigned:        "dqw324124123",
		GoogleClientID:     os.Getenv("OPENID_GOOGLE_CLIENT"),
		GoogleClientSecret: os.Getenv("OPENID_GOOGLE_SECRET"),
		CreateClaims:       DefaultCreateClaims,
		ExtensionIDs:       []string{},
	}
)

func New(service *goa.Service) goa.Middleware {
	return WithConfig(service, nil)
}

func WithConfig(service *goa.Service, conf *GoaGloginConf) goa.Middleware {

	if conf == nil {
		conf = &DefaultGoaGloginConf
	}
	// start url redirect to google
	service.Mux.Handle("GET", conf.LoginURL, makeAuthHandler(service, conf))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.LoginURL)

	// callback url and state check and get AccessToken
	service.Mux.Handle("GET", conf.CallbackURL, makeOauth2callbackHandler(service, conf))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.CallbackURL)

	// 横断的には何もしない
	return func(h goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			return h(c, rw, req)
		}
	}
}
