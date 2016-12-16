package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrUnauthorized = errors.New("jwtauth: unauthorized token")
	ErrExpired      = errors.New("jwtauth: expired token")
)

type JwtAuth struct {
	signKey   []byte
	verifyKey []byte
	signer    jwt.SigningMethod
	parser    *jwt.Parser
}

// New creates a JwtAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
func New(signer jwt.SigningMethod, signKey []byte, verifyKey []byte) *JwtAuth {
	return &JwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    signer,
	}
}

// NewWithParser is the same as New, except it supports custom parser settings
// introduced in ver. 2.4.0 of jwt-go
func NewWithParser(signer jwt.SigningMethod, parser *jwt.Parser, signKey []byte, verifyKey []byte) *JwtAuth {
	return &JwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    signer,
		parser:    parser,
	}
}

// Verifier middleware will verify a JWT passed by a client request.
// The Verifier will look for a JWT token from:
// 1. 'jwt' URI query parameter
// 2. 'Authorization: BEARER T' request header
// 3. Cookie 'jwt' value
//
// The verification processes finishes here and sets the token and
// a error in the request context and calls the next handler.
//
// Make sure to have your own handler following the Validator that
// will check the value of the "jwt" and "jwt.err" in the context
// and respond to the client accordingly. A generic Authenticator
// middleware is provided by this package, that will return a 401
// message for all unverified tokens, see jwtauth.Authenticator.
func (ja *JwtAuth) Verifier(next http.Handler) http.Handler {
	return ja.Verify("")(next)
}

func (ja *JwtAuth) Verify(paramAliases ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			var tokenStr string
			var err error
			var token *jwt.Token

			// Get token from query params
			tokenStr = r.URL.Query().Get("jwt")

			// Get token from other query param aliases
			if tokenStr == "" && paramAliases != nil && len(paramAliases) > 0 {
				for _, p := range paramAliases {
					tokenStr = r.URL.Query().Get(p)
					if tokenStr != "" {
						break
					}
				}
			}

			// Get token from authorization header
			if tokenStr == "" {
				bearer := r.Header.Get("Authorization")
				if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
					tokenStr = bearer[7:]
				}
			}

			// Get token from cookie
			if tokenStr == "" {
				if cookie, cookieErr := r.Cookie("jwt"); cookieErr == nil {
					tokenStr = cookie.Value
				}
			}

			if tokenStr == "" {
				err = ErrUnauthorized
			} else if token, err = ja.Decode(tokenStr); err != nil {
				// Verify the token
				switch err.Error() {
				case "Token is expired":
					err = ErrExpired
				}
			} else if token == nil || !token.Valid || token.Method != ja.signer {
				err = ErrUnauthorized
			} else if IsExpired(token) {
				// Check expiry via "exp" claim
				err = ErrExpired
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "jwt", token)
			ctx = context.WithValue(ctx, "jwt.err", err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func (ja *JwtAuth) Encode(claims jwt.Claims) (t *jwt.Token, tokenString string, err error) {
	t = jwt.NewWithClaims(ja.signer, claims)
	tokenString, err = t.SignedString(ja.signKey)
	// t.Raw = tokenString
	return
}

func (ja *JwtAuth) Decode(tokenString string) (*jwt.Token, error) {
	// Decode the tokenString, but avoid using custom Claims via jwt-go's
	// ParseWithClaims as the jwt-go types will cause some glitches, so easier
	// to decode as MapClaims then wrap the underlying map[string]interface{}
	// to our Claims type
	parse := jwt.Parse
	if ja.parser != nil {
		parse = ja.parser.Parse
	}
	return parse(tokenString, ja.keyFunc)
}

func (ja *JwtAuth) keyFunc(t *jwt.Token) (interface{}, error) {
	if ja.verifyKey != nil && len(ja.verifyKey) > 0 {
		return ja.verifyKey, nil
	} else {
		return ja.signKey, nil
	}
}

// Authenticator is a default authentication middleware to enforce access following
// the Verifier middleware. The Authenticator sends a 401 Unauthorized response for
// all unverified tokens and passes the good ones through. It's just fine until you
// decide to write something similar and customize your client response.
func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if jwtErr, ok := ctx.Value("jwt.err").(error); ok {
			if jwtErr != nil {
				http.Error(w, http.StatusText(401), 401)
				return
			}
		}

		jwtToken, ok := ctx.Value("jwt").(*jwt.Token)
		if !ok || jwtToken == nil || !jwtToken.Valid {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper function that returns the NumericDate time value used by the spec
func EpochNow() int64 {
	return time.Now().UTC().Unix()
}

// Helper function to return calculated time in the future for "exp" claim.
func ExpireIn(tm time.Duration) int64 {
	return EpochNow() + int64(tm.Seconds())
}

func IsExpired(t *jwt.Token) bool {
	claims := t.Claims.(jwt.MapClaims)

	if expv, ok := claims["exp"]; ok {
		var exp int64
		switch v := expv.(type) {
		case float64:
			exp = int64(v)
		case int64:
			exp = v
		case json.Number:
			exp, _ = v.Int64()
		default:
		}

		if exp < EpochNow() {
			return true
		}
	}

	return false
}
