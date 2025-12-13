package api

import (
	"context"
	"net/http"

	"os"

	"github.com/golang-jwt/jwt/v5"
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

	p := jwt.NewParser(parserOption)
	token, err := p.ParseWithClaims(bearer, &GatewayClaims{}, func(token *jwt.Token) (interface{}, error) {

		if config.JWT.Algorithm == "RS256" {
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
