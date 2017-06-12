package goagooglelogin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

func TestMakeClaims(t *testing.T) {
	mySigningKey := []byte("AllYourBase")
	claims := MakeClaim("testScope", "sampleID", 20)
	err := claims.Valid()
	if err != nil {
		t.Errorf("claims not valid..")
	}
	token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS512, claims)
	ss, err := token.SignedString(mySigningKey)
	if err != nil {
		t.Errorf("SignedString error")
	}

	fmt.Println(ss)

}

func TestHandler(t *testing.T) {

}
func TestClaim(t *testing.T) {
	var securtyScheme *goa.JWTSecurity
	var respRecord *httptest.ResponseRecorder
	var request *http.Request
	var handler goa.Handler
	var fetchedToken *jwtpkg.Token
	var middleware goa.Middleware
	var dispatchResult error

	securtyScheme = &goa.JWTSecurity{
		In:   goa.LocHeader,
		Name: "Authorization",
	}

	respRecord = httptest.NewRecorder()
	request, _ = http.NewRequest("GET", "http://example.com", nil)
	request.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZXMiOiJzY29wZTEiLCJhZG1pbiI6dHJ1ZX0.UCvEfbD_yuS5dCZidxZgogVi2yF0ZVecMsQQbY1HJy0")

	handler = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		fetchedToken = jwt.ContextJWT(ctx)
		return nil
	}

	middleware = jwt.New("keys", nil, securtyScheme)
	dispatchResult = middleware(handler)(context.Background(), respRecord, request)
	fmt.Println(dispatchResult)
	fmt.Println(respRecord)
}
