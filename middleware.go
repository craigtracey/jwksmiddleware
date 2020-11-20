package jwksmiddleware

import (
	"crypto/rsa"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
)

type JWTConfig struct {
	JWKSURL string
	middleware.JWTConfig
}

func getJWKSKeys(url string) (map[string]interface{}, error) {
	set, err := jwk.FetchHTTP(url)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]interface{})
	for _, key := range set.Keys {
		var val rsa.PublicKey
		err := key.Raw(&val)
		if err != nil {
			return nil, err
		}
		keys[key.KeyID()] = &val
	}

	return keys, nil
}

func JWTWithConfig(config JWTConfig) echo.MiddlewareFunc {
	keys, err := getJWKSKeys(config.JWKSURL)
	if err != nil {
		log.Panicf("Unable to fetch JWKS Keys: %s", err)
	}
	config.SigningKeys = keys
	return middleware.JWTWithConfig(config.JWTConfig)
}
