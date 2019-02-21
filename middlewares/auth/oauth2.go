package auth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares"
	"github.com/pkg/errors"
	"github.homedepot.com/dhp236e/go-web-security/provider/oauth2"
	"github.homedepot.com/dhp236e/go-web-security/provider/oauth2/token"
	"net/http"
	"net/url"
)

var ErrPublicKeyRequiredForJWT = errors.New("publicKey is required for JWT")
var ErrEndpointRequiredForRFC7662 = errors.New("endpoint value is required for rfc7662 token introspector")
var ErrMalformedMultiplexIntrospectorConfig = errors.New("mal formed multiplexing introspector config: no 'ref' element")

func buildTokenIntrospectors(introspectorConfig map[string]*config.OAuth2TokenIntrospector) (map[string]token.TokenIntrospector, error) {
	introspectors := make(map[string]token.TokenIntrospector)
	multiIntrospectorNames := make([]string, 0, 16)
	for name, tokenIntrospectorConfig := range introspectorConfig {
		var introspector token.TokenIntrospector
		switch tokenIntrospectorConfig.Type {
		case "jwt":
			if len(tokenIntrospectorConfig.PublicKey) == 0 {
				return nil, ErrPublicKeyRequiredForJWT
			}
			pubBlock, _ := pem.Decode([]byte(tokenIntrospectorConfig.PublicKey))
			if pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err == nil {
				if introspector, err = token.NewJWTTokenIntrospector(pubKey); err != nil {
					return nil, err
				}
			}
		case "rfc7662":
			if len(tokenIntrospectorConfig.Endpoint) > 0 {
				if endpoint, err := url.Parse(tokenIntrospectorConfig.Endpoint); err == nil {
					introspector = token.NewOAuth2TokenIntrospector(http.DefaultClient, endpoint)
				} else {
					return nil, fmt.Errorf("endpoint value is must be a well formed URL for the rfc7662 token introspector: %s", err.Error())
				}
			} else {
				return nil, ErrEndpointRequiredForRFC7662
			}
		case "multi":
			// Defer building multi introspectors until after all the others are defined.
			multiIntrospectorNames = append(multiIntrospectorNames, name)
		}
		if introspector != nil {
			introspectors[name] = introspector
		}
	}
	// run through the multi introspectors and build them.
	for _, name := range multiIntrospectorNames {
		tokenIntrospectorConfig := introspectorConfig[name]
		multiIntrospectors := make([]token.TokenIntrospector, 0, 16)
		if tokenIntrospectorConfig.Introspectors == nil || len(tokenIntrospectorConfig.Introspectors) == 0 {
			for _, introspectorRef := range tokenIntrospectorConfig.Introspectors {
				if intro, ok := introspectors[introspectorRef.Ref]; ok {
					multiIntrospectors = append(multiIntrospectors, intro)
				} else {
					return nil, fmt.Errorf("unknown token introspector: %s", introspectorRef.Ref)
				}
			}
		} else {
			return nil, ErrMalformedMultiplexIntrospectorConfig
		}
		introspectors[name] = token.NewMultiplexedTokenIntrospector(multiIntrospectors)
	}
	return introspectors, nil
}

func buildAccessRules(introspectors map[string]token.TokenIntrospector, accessRules []*config.OAuth2AccessRule) ([]*oauth2.AccessRule, error) {
	return nil, nil
}

func buildOAuth2Config(authConfig *config.OAuth2Auth) (*oauth2.OAuth2Config, error) {
	if introspectors, err := buildTokenIntrospectors(authConfig.TokenIntrospectors); err != nil {
		if accessRules, err := buildAccessRules(introspectors, authConfig.AccessRules); err != nil {
			return &oauth2.OAuth2Config{
				accessRules,
				authConfig.Realm,
			}, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

func NewOAuth2(ctx context.Context, next http.Handler, authConfig *config.OAuth2Auth, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, digestTypeName).Debug("Creating middleware")
	if oAuth2Config, err := buildOAuth2Config(authConfig); err != nil {
		oa := oauth2.NewOAuth2Provider(oAuth2Config)

		return oa, err
	} else {
		return nil, err
	}
	return nil, nil
}
