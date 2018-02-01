package goagooglelogin

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"
	v2 "google.golang.org/api/oauth2/v2"
)

var (
	conf = oauth2.Config{
		Scopes: []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://www.googleapis.com/oauth2/v4/token",
		},
	}
)

// makeAuthHandler is created redirectURL and access redirectURL
func makeAuthHandler(service *goa.Service, loginConf *GoaGloginConf) goa.Handler {
	conf.ClientID = loginConf.GoogleClientID
	conf.ClientSecret = loginConf.GoogleClientSecret
	return func(ctx context.Context, rw http.ResponseWriter, r *http.Request) error {
		nextURL := r.URL.Query().Get("next_url")
		if nextURL == "" {
			nextURL = "/"
		}

		redirectURL := url.URL{}
		redirectURL.Path = loginConf.CallbackURL
		redirectURL.Host = r.Host
		if r.TLS == nil {
			redirectURL.Scheme = "http"
		} else {
			redirectURL.Scheme = "https"
		}

		conf.RedirectURL = redirectURL.String()
		service.LogInfo("mount", "middleware", "goagooglelogin", "redirectURL.String()", redirectURL.String())
		claims := &jwtgo.MapClaims{
			// TODO この箇所でGoogleログイン画面の認証にかかる時間の限界が決まる。つまり本来オプションにすべき時間はここ
			"exp":          time.Now().Add(time.Duration(5) * time.Minute).Unix(),
			"redirect_url": nextURL,
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
		state, err := token.SignedString([]byte(loginConf.StateSigned))
		if err != nil {
			service.LogInfo("mount", "middleware", "goagooglelogin", "state", state)
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}
		url := conf.AuthCodeURL(state)
		service.LogInfo("mount", "middleware", "goagooglelogin", "url", url)
		http.Redirect(rw, r, url, 302)
		return nil
	}
}

// InValid はValidでerrorを返すInValid専用型
type InValid struct {
	err error
}

var _ jwtgo.Claims = InValid{nil}

// Valid はjwtgo.Claimsを満たす
func (in InValid) Valid() error {
	return in.err
}

// MakeClaim is CreateFunction for login JWT claims
func MakeClaim(scopes string, googleID string, expireMinute int) jwtgo.Claims {

	uuidV4, err := uuid.NewV4()
	if err != nil {
		return InValid{err}
	}
	inXm := time.Now().Add(time.Duration(expireMinute) * time.Minute).Unix()
	return jwtgo.MapClaims{
		"iss":    "goaglogin",       // who creates the token and signs it
		"exp":    inXm,              // time when the token will expire (X minutes from now)
		"jti":    uuidV4.String(),   // a unique identifier for the token
		"iat":    time.Now().Unix(), // when the token was issued/created (now)
		"sub":    googleID,          // the subject/principal is whom the token is about
		"scopes": scopes,            // token scope - not a standard claim
	}
}

// DefaultCreateClaims is basic save user info function
func DefaultCreateClaims(
	ctx context.Context,
	googleUserID string,
	userInfo *v2.Userinfoplus,
	tokenInfo *v2.Tokeninfo,
) (claims jwtgo.Claims, err error) {

	// resp, err := http.Get(userInfo.Picture)
	// if err != nil {
	// 	return
	// }

	// defer resp.Body.Close()
	// picture, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return
	// }

	// fmt.Println(len(picture))

	// sample save code
	// account := &models.Account{}
	// account, err = models.AccountByGoogleUserID(option.db, googleUserID)
	// if err != nil {
	// 	account = &models.Account{
	// 		GoogleUserID: googleUserID,
	// 		Image:        picture,
	// 		Email:        userInfo.Email,
	// 		Name:         userInfo.Name,
	// 		Created:      time.Now(),
	// 	}
	// 	err = account.Insert(option.db)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	return MakeClaim("api:access", googleUserID, 1), nil
}

// createSignedToken is token creater
func createSignedToken(claims jwtgo.Claims, loginConf *GoaGloginConf) (string, error) {
	if loginConf == nil {
		loginConf = &DefaultGoaGloginConf
	}

	signedToken := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, claims)
	signedTokenStr, err := signedToken.SignedString([]byte(loginConf.LoginSigned))
	if err != nil {
		return "", err
	}

	return signedTokenStr, nil
}

// WithJWTClaims is test helper
func WithJWTClaims(ctx context.Context, claims jwtgo.Claims) context.Context {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, claims)
	return jwt.WithJWT(ctx, token)
}
