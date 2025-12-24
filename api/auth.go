package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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

// extractKID extracts the kid (key ID) from the JWT header without verifying the signature
func extractKID(bearer string) (string, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return "", unauthorizedError("Invalid token format")
	}

	// Decode the header (first part)
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return "", unauthorizedError("Invalid token header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", unauthorizedError("Invalid token header: %v", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return "", unauthorizedError("Invalid token: no kid header present")
	}

	return kid, nil
}

// decodeBase64URL decodes base64 URL-encoded data
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	config := getConfig(r.Context())

	var claims GatewayClaims
	var algorithm jwa.SignatureAlgorithm
	var key any
	var err error

	if config.JWT.Algorithm == "RS256" {
		algorithm = jwa.RS256()
		key, err = a.loadRS256Key(bearer, r)
		if err != nil {
			return nil, err
		}
	} else {
		// HS256 with shared secret
		algorithm = jwa.HS256()
		key = []byte(config.JWT.Secret)
	}

	token, err := jwt.ParseString(bearer, jwt.WithKey(algorithm, key))
	if err != nil {
		return nil, unauthorizedError("Invalid token: %v", err)
	}

	extractClaimsFromToken(token, &claims)

	// Validate audience if specified
	if config.JWT.Audience != "" {
		if !validateAudience(token, config.JWT.Audience) {
			return nil, unauthorizedError("Invalid token: audience mismatch")
		}
	}

	return withToken(r.Context(), &claims), nil
}

// loadRS256Key loads the RS256 key from JWK cache or from a file
func (a *API) loadRS256Key(bearer string, r *http.Request) (any, error) {
	config := getConfig(r.Context())

	// Read JWKs URL if provided
	if len(strings.TrimSpace(config.JWT.JwksURL)) != 0 {
		return a.loadKeyFromJWKCache(bearer, r)
	}

	// Fallback to Public Key file
	return a.loadKeyFromFile(config.JWT.PublicKey)
}

// loadKeyFromJWKCache loads a key from the JWK cache using the kid header
func (a *API) loadKeyFromJWKCache(bearer string, r *http.Request) (any, error) {
	config := getConfig(r.Context())

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

	// Get kid from unverified token
	kid, err := extractKID(bearer)
	if err != nil {
		return nil, err
	}

	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, unauthorizedError("Invalid token: unknown kid %s", kid)
	}

	return key, nil
}

// loadKeyFromFile loads a key from a PEM-encoded file
func (a *API) loadKeyFromFile(keyPath string) (any, error) {
	dat, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	key, err := jwk.ParseKey(dat, jwk.WithPEM(true))
	if err != nil {
		return nil, unauthorizedError("Invalid token: failed to parse public key: %v", err)
	}

	return key, nil
}

// extractClaimsFromToken extracts custom and standard claims from a JWT token
func extractClaimsFromToken(token jwt.Token, claims *GatewayClaims) {
	// Extract custom claims
	if err := token.Get("email", &claims.Email); err == nil {
		// Field exists
	}
	if err := token.Get("app_metadata", &claims.AppMetaData); err == nil {
		// Field exists
	}
	if err := token.Get("user_metadata", &claims.UserMetaData); err == nil {
		// Field exists
	}
	extractStandardClaims(token, claims)
}

// validateAudience checks if the token's audience matches the expected audience
func validateAudience(token jwt.Token, expectedAudience string) bool {
	aud, ok := token.Audience()
	if !ok {
		return false
	}
	for _, a := range aud {
		if a == expectedAudience {
			return true
		}
	}
	return false
}

// extractStandardClaims extracts standard JWT claims from a token
func extractStandardClaims(token jwt.Token, claims *GatewayClaims) {
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
	if nbf, ok := token.NotBefore(); ok {
		claims.Nbf = nbf.Unix()
	}
}
