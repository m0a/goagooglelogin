package goagooglelogin

import (
	"context"
	"errors"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa/middleware/security/jwt"
)

// GoogleIDByJWTContext return googleID by Context
func GoogleIDByJWTContext(ctx context.Context) (string, error) {
	jwtContext := jwt.ContextJWT(ctx)
	if jwtContext == nil {
		return "", errors.New("jwtContext is nil")
	}
	claims, ok := jwtContext.Claims.(jwtgo.MapClaims)
	if !ok {
		return "", errors.New("not get jwt-go.MapClaims")
	}
	googleID, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("not get googleID")
	}
	return googleID, nil
}