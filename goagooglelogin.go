package goagooglelogin

import (
	"context"
	"net/http"

	"github.com/goadesign/goa"
	"google.golang.org/api/oauth2/v2"
)

type (
	// GoaGloginConf middleware config
	GoaGloginConf struct {
		LoginURL     string
		CallbackURL  string
		StateSigned  string
		LoginSigned  string
		ExpireMinute int
		SaveUserInfo func(googleUserID string, userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo) error
	}
)

var (
	// DefaultGoaGloginConf is the default googlelogin middleware config.
	DefaultGoaGloginConf = GoaGloginConf{
		LoginURL:     "/login",
		CallbackURL:  "/oauth2callback",
		StateSigned:  "testa1234",
		LoginSigned:  "12345678test",
		ExpireMinute: 2,
		SaveUserInfo: DefaultSaveUserInfo,
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
	service.Mux.Handle("GET", conf.LoginURL, MakeAuthHandler(service, conf))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.LoginURL)

	// callback url and state check and get AccessToken
	service.Mux.Handle("GET", conf.CallbackURL, MakeOauth2callbackHandler(service, conf))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.CallbackURL)

	// 横断的には何もしない
	return func(h goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			return h(c, rw, req)
		}
	}
}
