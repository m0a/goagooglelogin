package goagooglelogin

import (
	"context"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"google.golang.org/api/oauth2/v2"
)

// CreateClaimFunction is GoaGloginConf.CreateClaim Type
type CreateClaimFunction func(
	googleUserID string,
	userinfo *oauth2.Userinfoplus,
	tokenInfo *oauth2.Tokeninfo,
	ctx context.Context) (jwt.Claims, error)

type (
	// GoaGloginConf middleware config
	GoaGloginConf struct {
		LoginURL           string // defualt: /login
		CallbackURL        string // default: /oauth2callback
		StateSigned        string // state JWT key
		LoginSigned        string // login JWT key
		GoogleClientID     string
		GoogleClientSecret string
		CreateClaims       CreateClaimFunction
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

// MessageController implements the message resource.
type GoaGLoginController struct {
	*goa.Controller
}

// newGoaGLoginController creates a goa google login controller.
func newGoaGLoginController(service *goa.Service) *GoaGLoginController {
	return &GoaGLoginController{Controller: service.NewController("GoaGLoginController")}
}

func New(service *goa.Service) goa.Middleware {
	return WithConfig(service, nil)
}

func WithConfig(service *goa.Service, conf *GoaGloginConf) goa.Middleware {

	if conf == nil {
		conf = &DefaultGoaGloginConf
	}
	ctrl := newGoaGLoginController(service)

	// start url redirect to google
	service.Mux.Handle("GET", conf.LoginURL, ctrl.MuxHandler("login", makeAuthHandler(service, conf), nil))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.LoginURL)

	// callback url and state check and get AccessToken
	service.Mux.Handle("GET", conf.CallbackURL, ctrl.MuxHandler("callback", makeOauth2callbackHandler(service, conf), nil))
	service.LogInfo("mount", "middleware", "goagooglelogin", "route", "GET "+conf.CallbackURL)

	// 横断的には何もしない
	return func(h goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			return h(c, rw, req)
		}
	}
}
