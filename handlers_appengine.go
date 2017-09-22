// +build appengine

package goagooglelogin

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	v2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/appengine"
)

func makeOauth2callbackHandler(service *goa.Service, loginConf *GoaGloginConf) goa.Handler {
	return func(ctx context.Context, rw http.ResponseWriter, r *http.Request) error {

		if loginConf == nil {
			loginConf = &DefaultGoaGloginConf
		}

		state := r.FormValue("state")
		t, err := jwtgo.Parse(state, func(*jwtgo.Token) (interface{}, error) {
			return []byte(loginConf.StateSigned), nil
		})
		if err != nil {
			http.Error(rw, "jwt.Parse err.", http.StatusUnauthorized)
			return nil
		}
		if !t.Valid {
			http.Error(rw, "state is invalid.", http.StatusUnauthorized)
			return nil
		}

		mapClaims, ok := t.Claims.(jwtgo.MapClaims)
		if !ok {
			http.Error(rw, "claims is invalid.", http.StatusUnauthorized)
			return nil
		}
		service.LogInfo("mount", "middleware", "makeOauth2callbackHandler", "mapClaims", fmt.Sprintf("%#v", mapClaims))
		temp, ok := mapClaims["redirect_url"]
		if !ok {
			http.Error(rw, "mapClaims[redirect_url] is invalid.", http.StatusUnauthorized)
			return nil
		}

		redirectURL, ok := temp.(string)
		if !ok {
			http.Error(rw, "mapClaims[redirect_url] string is invalid.", http.StatusUnauthorized)
			return nil
		}

		// 認証コードを取得します
		code := r.FormValue("code")
		context := appengine.WithContext(ctx, r)
		// 認証コードからtokenを取得します
		tok, err := conf.Exchange(context, code)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}
		// tokenが正しいことを確認します
		if tok.Valid() == false {
			http.Error(rw, "token is invalid.", http.StatusUnauthorized)
			return nil
		}

		// oauth2 clinet serviceを取得します
		oAuthservice, err := v2.New(conf.Client(context, tok))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}

		// token情報を取得します
		// ここにEmailやUser IDなどが入っています
		tokenInfo, err := oAuthservice.Tokeninfo().AccessToken(tok.AccessToken).Context(context).Do()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}

		userInfo, err := oAuthservice.Userinfo.Get().Do()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}

		if loginConf.CreateClaims == nil {
			http.Error(rw, "expect define conf.CreateClaims", http.StatusUnauthorized)
			return nil
		}

		googleUserID := tokenInfo.UserId
		service.LogInfo("mount", "middleware", "MakeOauth2callbackHandler", "CreateClaims googleUserID", googleUserID)
		claims, err := loginConf.CreateClaims(googleUserID, userInfo, tokenInfo, context)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}

		signedTokenStr, err := CreateSignedToken(claims, loginConf)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
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

			let extensionIds = JSON.parse({{.ExtensionIDs}});
			for (let id of extensionIds) {
				console.log('send to: '+ id + ' jwt: '+ token);
				chrome.runtime.sendMessage(id, { jwt: token });
			}

			location.href = '{{.RedirectURL}}';
		</script>	
	</head>
</html>
		`)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}

		type templateItem struct {
			SignedToken  string
			RedirectURL  string
			ExtensionIDs string
		}

		extensionIds, err := json.Marshal(loginConf.ExtensionIDs)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}
		items := templateItem{
			SignedToken:  signedTokenStr,
			RedirectURL:  redirectURL,
			ExtensionIDs: string(extensionIds),
		}

		err = tmpl.Execute(rw, items)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return nil
		}
		return nil
	}
}
