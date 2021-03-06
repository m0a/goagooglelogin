// Code generated by goagen v1.3.0, DO NOT EDIT.
//
// unnamed API: Application Contexts
//
// Command:
// $ goagen
// --design=github.com/m0a/goagooglelogin/examples/gae/design
// --out=$(GOPATH)/src/github.com/m0a/goagooglelogin/examples/gae
// --version=v1.3.0

package app

import (
	"context"
	"github.com/goadesign/goa"
	"net/http"
)

// SecureJWTContext provides the jwt secure action context.
type SecureJWTContext struct {
	context.Context
	*goa.ResponseData
	*goa.RequestData
}

// NewSecureJWTContext parses the incoming request URL and body, performs validations and creates the
// context used by the jwt controller secure action.
func NewSecureJWTContext(ctx context.Context, r *http.Request, service *goa.Service) (*SecureJWTContext, error) {
	var err error
	resp := goa.ContextResponse(ctx)
	resp.Service = service
	req := goa.ContextRequest(ctx)
	req.Request = r
	rctx := SecureJWTContext{Context: ctx, ResponseData: resp, RequestData: req}
	return &rctx, err
}

// OK sends a HTTP response with status code 200.
func (ctx *SecureJWTContext) OK(r *GoaExamplesSecuritySecure) error {
	ctx.ResponseData.Header().Set("Content-Type", "application/vnd.goa.examples.security.secure+json")
	return ctx.ResponseData.Service.Send(ctx.Context, 200, r)
}

// Unauthorized sends a HTTP response with status code 401.
func (ctx *SecureJWTContext) Unauthorized() error {
	ctx.ResponseData.WriteHeader(401)
	return nil
}

// UnsecureJWTContext provides the jwt unsecure action context.
type UnsecureJWTContext struct {
	context.Context
	*goa.ResponseData
	*goa.RequestData
}

// NewUnsecureJWTContext parses the incoming request URL and body, performs validations and creates the
// context used by the jwt controller unsecure action.
func NewUnsecureJWTContext(ctx context.Context, r *http.Request, service *goa.Service) (*UnsecureJWTContext, error) {
	var err error
	resp := goa.ContextResponse(ctx)
	resp.Service = service
	req := goa.ContextRequest(ctx)
	req.Request = r
	rctx := UnsecureJWTContext{Context: ctx, ResponseData: resp, RequestData: req}
	return &rctx, err
}

// OK sends a HTTP response with status code 200.
func (ctx *UnsecureJWTContext) OK(r *Success) error {
	ctx.ResponseData.Header().Set("Content-Type", "application/vnd.goa.examples.security.success")
	return ctx.ResponseData.Service.Send(ctx.Context, 200, r)
}
