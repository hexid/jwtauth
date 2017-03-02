package jwtauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type contextKey int

const (
	JwtContextKey contextKey = iota
	JwtErrContextKey
)

type JwtAuth struct {
	signKey   interface{}
	verifyKey interface{}
	signer    jwt.SigningMethod
	parser    *jwt.Parser
}

// New creates a JwtAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
func New(signer jwt.SigningMethod, signKey, verifyKey interface{}) *JwtAuth {
	return &JwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    signer,
	}
}

// NewWithParser is the same as New, except it supports custom parser settings
// introduced in ver. 2.4.0 of jwt-go
func NewWithParser(signer jwt.SigningMethod, parser *jwt.Parser, signKey, verifyKey interface{}) *JwtAuth {
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
			var ctx context.Context

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

			if token, err = ja.Decode(tokenStr); token != nil {
				if token.Method != ja.signer {
					err = &jwt.ValidationError{
						Inner:  fmt.Errorf("token signing method %v does not match %v", token.Method, ja.signer),
						Errors: jwt.ValidationErrorSignatureInvalid,
					}
				}
			} else if token == nil {
				err = &jwt.ValidationError{
					Inner:  fmt.Errorf("token parsing failed unexpectedly"),
					Errors: jwt.ValidationErrorMalformed,
				}
			}

			ctx = r.Context()
			ctx = context.WithValue(ctx, JwtContextKey, token)
			ctx = context.WithValue(ctx, JwtErrContextKey, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func (ja *JwtAuth) Encode(claims jwt.Claims) (*jwt.Token, string, error) {
	t := jwt.NewWithClaims(ja.signer, claims)
	tokenString, err := t.SignedString(ja.signKey)
	t.Raw = tokenString
	return t, tokenString, err
}

// Decode the tokenString with the default parser, unless another is provided.
func (ja *JwtAuth) Decode(tokenString string) (*jwt.Token, error) {
	parse := jwt.Parse
	if ja.parser != nil {
		parse = ja.parser.Parse
	}
	return parse(tokenString, ja.keyFunc)
}

func (ja *JwtAuth) keyFunc(t *jwt.Token) (interface{}, error) {
	if ja.verifyKey != nil {
		return ja.verifyKey, nil
	}
	return ja.signKey, nil
}

// Authenticator is a default authentication middleware to enforce access following
// the Verifier middleware. The Authenticator sends a 401 Unauthorized response for
// all unverified tokens and passes the good ones through. It's just fine until you
// decide to write something similar and customize your client response.
func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if jwtErr, ok := ctx.Value(JwtErrContextKey).(error); ok && jwtErr != nil {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		// jwtToken, ok := ctx.Value(JwtContextKey).(*jwt.Token)
		// if !ok || jwtToken == nil || !jwtToken.Valid {
		// 	http.Error(w, http.StatusText(401), 401)
		// 	return
		// }

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
