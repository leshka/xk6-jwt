package jwt

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
	"time"
)

type Jwt struct{}

type Encoder struct {
	issuer       string
	audience     string
	privateKey   string
	privateKeyID string
}

func (j *Jwt) XEncoder(ctxPtr *context.Context, issuer, audience, privateKey, privateKeyID string) interface{} {
	rt := common.GetRuntime(*ctxPtr)
	return common.Bind(rt, &Encoder{
		issuer:       issuer,
		audience:     audience,
		privateKey:   privateKey,
		privateKeyID: privateKeyID,
	}, ctxPtr)
}

func (e *Encoder) Token() string {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(e.privateKey))
	if err != nil {
		panic(err)
	}
	claims := &jwt.StandardClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * 24)).Unix(),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()).Unix(),
		Issuer:    e.issuer,
		Audience:  e.audience,
	}
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": "RS256",
			"kid": e.privateKeyID,
		},
		Claims: claims,
		Method: jwt.SigningMethodRS256,
	}
	ss, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return ss
}

func init() {
	modules.Register("k6/x/jwt", new(Jwt))
}
