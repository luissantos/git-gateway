package api

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/netlify/git-gateway/models"
)

const (
	jwsSignatureHeaderName = "x-nf-sign"
)

type NetlifyMicroserviceClaims struct {
	SiteURL    string `json:"site_url"`
	InstanceID string `json:"id"`
	NetlifyID  string `json:"netlify_id"`
	// Use the standard jwt package's StandardClaims equivalent for lestrrat-go
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud []string `json:"aud"`
	Exp int64    `json:"exp"`
	Iat int64    `json:"iat"`
}

func (a *API) loadJWSSignatureHeader(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	signature := r.Header.Get(jwsSignatureHeaderName)
	if signature == "" {
		return nil, badRequestError("Operator microservice headers missing")
	}
	return withSignature(ctx, signature), nil
}

func (a *API) loadInstanceConfig(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()

	signature := getSignature(ctx)
	if signature == "" {
		return nil, badRequestError("Operator signature missing")
	}

	// Parse and verify the JWT with HS256
	token, err := jwt.ParseString(signature, jwt.WithKey(jwa.HS256(), []byte(a.config.OperatorToken)))
	if err != nil {
		return nil, badRequestError("Operator microservice signature is invalid: %v", err)
	}

	claims := NetlifyMicroserviceClaims{}

	// Extract custom claims
	if err := token.Get("site_url", &claims.SiteURL); err == nil {
		// Field exists
	}
	if err := token.Get("id", &claims.InstanceID); err == nil {
		// Field exists
	}
	if err := token.Get("netlify_id", &claims.NetlifyID); err == nil {
		// Field exists
	}

	// Extract standard claims
	if iss, ok := token.Issuer(); ok {
		claims.Iss = iss
	}
	if sub, ok := token.Subject(); ok {
		claims.Sub = sub
	}
	if aud, ok := token.Audience(); ok {
		claims.Aud = aud
	}
	if exp, ok := token.Expiration(); ok {
		claims.Exp = exp.Unix()
	}
	if iat, ok := token.IssuedAt(); ok {
		claims.Iat = iat.Unix()
	}

	instanceID := claims.InstanceID
	if instanceID == "" {
		return nil, badRequestError("Instance ID is missing")
	}

	logEntrySetField(r, "instance_id", instanceID)
	logEntrySetField(r, "netlify_id", claims.NetlifyID)
	instance, err := a.db.GetInstance(instanceID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError("Unable to locate site configuration")
		}
		return nil, internalServerError("Database error loading instance").WithInternalError(err)
	}

	config, err := instance.Config()
	if err != nil {
		return nil, internalServerError("Error loading environment config").WithInternalError(err)
	}

	ctx = withNetlifyID(ctx, claims.NetlifyID)
	ctx, err = WithInstanceConfig(ctx, config, instanceID)
	if err != nil {
		return nil, internalServerError("Error loading instance config").WithInternalError(err)
	}

	return ctx, nil
}

func (a *API) verifyOperatorRequest(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	c, _, err := a.extractOperatorRequest(w, req)
	return c, err
}

func (a *API) extractOperatorRequest(w http.ResponseWriter, req *http.Request) (context.Context, string, error) {
	token, err := a.extractBearerToken(w, req)
	if err != nil {
		return nil, token, err
	}
	if token == "" || token != a.config.OperatorToken {
		return nil, token, unauthorizedError("Request does not include an Operator token")
	}
	return req.Context(), token, nil
}
