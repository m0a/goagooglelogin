package goagooglelogin

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
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
func makeAuthHandler(service *goa.Service, loginConf *GoaGloginConf) goa.MuxHandler {
	conf.ClientID = loginConf.GoogleClientID
	conf.ClientSecret = loginConf.GoogleClientSecret
	return func(w http.ResponseWriter, r *http.Request, _ url.Values) {
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
		claims := &jwt.MapClaims{
			"exp":          time.Now().Add(time.Duration(30) * time.Second).Unix(),
			"redirect_url": nextURL,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		state, err := token.SignedString([]byte(loginConf.StateSigned))
		if err != nil {
			service.LogInfo("mount", "middleware", "goagooglelogin", "state", state)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		url := conf.AuthCodeURL(state)
		service.LogInfo("mount", "middleware", "goagooglelogin", "url", url)
		http.Redirect(w, r, url, 302)
	}
}

// MakeClaim is CreateFunction for login JWT claims
func MakeClaim(scopes string, googleID string, expireMinute int) jwt.Claims {

	inXm := time.Now().Add(time.Duration(expireMinute) * time.Minute).Unix()
	return jwt.MapClaims{
		"iss":    "goaglogin",           // who creates the token and signs it
		"exp":    inXm,                  // time when the token will expire (X minutes from now)
		"jti":    uuid.NewV4().String(), // a unique identifier for the token
		"iat":    time.Now().Unix(),     // when the token was issued/created (now)
		"sub":    googleID,              // the subject/principal is whom the token is about
		"scopes": scopes,                // token scope - not a standard claim
	}
}

// DefaultCreateClaims is basic save user info function
func DefaultCreateClaims(googleUserID string,
	userInfo *v2.Userinfoplus,
	tokenInfo *v2.Tokeninfo,
) (claims jwt.Claims, err error) {

	resp, err := http.Get(userInfo.Picture)
	if err != nil {
		return
	}

	defer resp.Body.Close()
	picture, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	fmt.Println(len(picture))

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
	return MakeClaim("api:access", googleUserID, 10), nil
}

func makeOauth2callbackHandler(service *goa.Service, loginConf *GoaGloginConf) goa.MuxHandler {
	return func(w http.ResponseWriter, r *http.Request, _ url.Values) {

		if loginConf == nil {
			loginConf = &DefaultGoaGloginConf
		}

		state := r.FormValue("state")
		t, err := jwt.Parse(state, func(*jwt.Token) (interface{}, error) {
			return []byte(loginConf.StateSigned), nil
		})
		if !t.Valid {
			http.Error(w, "state is invalid.", http.StatusUnauthorized)
			return
		}

		mapClaims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "claims is invalid.", http.StatusUnauthorized)
			return
		}
		service.LogInfo("mount", "middleware", "makeOauth2callbackHandler", "mapClaims", fmt.Sprintf("%#v", mapClaims))
		temp, ok := mapClaims["redirect_url"]
		if !ok {
			http.Error(w, "mapClaims[redirect_url] is invalid.", http.StatusUnauthorized)
			return
		}

		redirectURL, ok := temp.(string)
		if !ok {
			http.Error(w, "mapClaims[redirect_url] string is invalid.", http.StatusUnauthorized)
			return
		}

		// 認証コードを取得します
		code := r.FormValue("code")
		context := context.Background()
		// 認証コードからtokenを取得します
		tok, err := conf.Exchange(context, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// tokenが正しいことを確認します
		if tok.Valid() == false {
			http.Error(w, "token is invalid.", http.StatusUnauthorized)
			return
		}

		// oauth2 clinet serviceを取得します
		oAuthservice, err := v2.New(conf.Client(context, tok))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// token情報を取得します
		// ここにEmailやUser IDなどが入っています
		tokenInfo, err := oAuthservice.Tokeninfo().AccessToken(tok.AccessToken).Context(context).Do()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userInfo, err := oAuthservice.Userinfo.Get().Do()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if loginConf.CreateClaims == nil {
			http.Error(w, "expect define SaveUserInfo", http.StatusUnauthorized)
			return
		}

		googleUserID := tokenInfo.UserId
		service.LogInfo("mount", "middleware", "MakeOauth2callbackHandler", "CreateClaims googleUserID", googleUserID)
		claims, err := loginConf.CreateClaims(googleUserID, userInfo, tokenInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		signedToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		signedTokenStr, err := signedToken.SignedString([]byte(loginConf.LoginSigned))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		tmpl, err := template.New("save_token").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<script>
			signedtoken ="{{.SignedToken}}";
			sessionStorage.setItem('signedtoken',signedtoken);
			let token = sessionStorage.getItem('signedtoken');
			var extensionId = "{{.ExtensionID}}";
			chrome.runtime.sendMessage(extensionId, { jwt: token });
			location.href = '{{.RedirectURL}}';
		</script>	
	</head>
</html>
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		type templateItem struct {
			SignedToken string
			RedirectURL string
			ExtensionID string
		}

		items := templateItem{
			SignedToken: signedTokenStr,
			RedirectURL: redirectURL,
			ExtensionID: loginConf.ExtensionID,
		}

		err = tmpl.Execute(w, items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

	}
}
