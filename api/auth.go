package api

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sirupsen/logrus"
)

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	logrus.Info("Getting auth token")
	token, err := a.extractBearerToken(w, r)
	if err != nil {
		return nil, err
	}

	logrus.Infof("Parsing JWT claims: %v", token)
	return a.parseJWTClaims(token, r)
}

func (a *API) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	config := getConfig(r.Context())
	parserOption := jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name})
	if config.JWT.Algorithm == "RS256" {
		parserOption = jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name})
	}

	audienceOption := jwt.WithAudience(config.JWT.Audience)

	p := jwt.NewParser(parserOption, audienceOption)
	token, err := p.ParseWithClaims(bearer, &GatewayClaims{}, func(token *jwt.Token) (interface{}, error) {

		if config.JWT.Algorithm == "RS256" {

			// Read JWKs URL if provided
			if len(strings.TrimSpace(config.JWT.JwksURL)) != 0 {
				if !a.jwkCache.IsRegistered(r.Context(), config.JWT.JwksURL) {
					err := a.jwkCache.Register(r.Context(), config.JWT.JwksURL)
					if err != nil {
						return nil, err
					}
				}

				set, err := a.jwkCache.Lookup(r.Context(), config.JWT.JwksURL)

				if err != nil {
					return nil, err
				}
				kid, ok := token.Header["kid"].(string)
				if !ok {
					return nil, unauthorizedError("Invalid token: no kid header present")
				}
				key, ok := set.LookupKeyID(kid)
				if !ok {
					return nil, unauthorizedError("Invalid token: unknown kid %s", kid)
				}

				// Convert jwk.Key to rsa.PublicKey using KeyExporter
				pubKey := rsa.PublicKey{}

				err = jwk.Export(key, &pubKey)

				if err != nil {
					return nil, err
				}

				return &pubKey, nil
			}

			// Fallback to Public Key file
			dat, err := os.ReadFile(config.JWT.PublicKey)
			if err != nil {
				return nil, err
			}
			pubKey, err := jwt.ParseRSAPublicKeyFromPEM(dat)
			if err != nil {
				return nil, err
			}
			return pubKey, nil
		}

		return []byte(config.JWT.Secret), nil
	})
	if err != nil {
		return nil, unauthorizedError("Invalid token: %v", err)
	}

	return withToken(r.Context(), token), nil
}
