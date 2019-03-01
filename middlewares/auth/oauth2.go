package auth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/bluesoftdev/go-http-matchers/extractor"
	"github.com/bluesoftdev/go-http-matchers/predicate"
	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares"
	"github.com/iancoleman/orderedmap"
	"github.com/pkg/errors"
	"github.homedepot.com/dhp236e/go-web-security/provider/oauth2"
	"github.homedepot.com/dhp236e/go-web-security/provider/oauth2/token"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
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
		fmt.Printf("tokenIntrosepctorConfig = %+v\n", tokenIntrospectorConfig)
		multiIntrospectors := make([]token.TokenIntrospector, 0, 16)
		if tokenIntrospectorConfig.Introspectors == nil || len(tokenIntrospectorConfig.Introspectors) > 0 {
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

func buildPredicatesArray(_conditions interface{}) ([]predicate.Predicate, error) {
	if conditions, ok := _conditions.([]interface{}); ok {
		predicates := make([]predicate.Predicate, len(conditions))
		for c, cnd := range conditions {
			switch sub := cnd.(type) {
			case orderedmap.OrderedMap:
				var err error
				if predicates[c], err = buildRequestCondition(&sub); err != nil {
					return nil, errors.Wrap(err, "error parsing request condition")
				}
			default:
				return nil, errors.Errorf("unexpected condition element: %+v", cnd)
			}
		}
		return predicates, nil
	} else {
		return nil, errors.Errorf("unexpected content for condition: %v", _conditions)
	}
}

var stringConditions = []string{"equals", "contains", "matches", "startsWith", "endsWith"}

func buildStringValueConditionPredicate(typ, v string) (predicate.Predicate, error) {
	switch typ {
	case "equals":
		return predicate.StringEquals(v), nil
	case "contains":
		return predicate.StringContains(v), nil
	case "matches":
		if rx, err := regexp.Compile(v); err == nil {
			return predicate.StringMatches(rx), nil
		} else {
			return nil, errors.Wrap(err, "parsing regex for string condition")
		}
	case "startsWith":
		return predicate.StringStartsWith(v), nil
	case "endsWith":
		return predicate.StringEndsWith(v), nil
	default:
		return nil, nil
	}
}

func buildStringValueCondition(condition interface{}) (predicate.Predicate, error) {
	switch cond := condition.(type) {
	case orderedmap.OrderedMap:
		for _, typ := range stringConditions {
			v, ok := cond.Get(typ)
			if ok {
				if pred, err := buildStringValueConditionPredicate(typ, v.(string)); err == nil {
					return pred, nil
				} else {
					return nil, err
				}
			}
		}
		return nil, errors.Errorf("unknown condition: %v", cond)
	case map[string]interface{}:
		for _, typ := range stringConditions {
			v, ok := cond[typ]
			if ok {
				if pred, err := buildStringValueConditionPredicate(typ, v.(string)); err == nil {
					return pred, nil
				} else {
					return nil, err
				}
			}
		}
		return nil, errors.Errorf("unknown condition: %v", cond)
	default:
		return nil, errors.Errorf("unexpected condition content: %+v", condition)
	}
}

func buildStringValuePredicate(condition interface{}, extr extractor.Extractor, name string) (predicate.Predicate, error) {
	if stringCond, err := buildStringValueCondition(condition); err == nil {
		return predicate.ExtractedValueAccepted(extr, stringCond), nil
	} else {
		return nil, errors.Wrapf(err, "building condition for '%s'", name)
	}
}

var arrayConditions = []string{"contains"}

func buildArrayValueConditionPredicate(typ, value string) (predicate.Predicate, error) {
	switch typ {
	case "contains":
		return containsPredicate(value), nil
	}
	return nil, errors.Errorf("unrecognized array operation: %s", typ)
}

func buildArrayValueCondition(condition orderedmap.OrderedMap) (predicate.Predicate, error) {
	for _, typ := range stringConditions {
		v, ok := condition.Get(typ)
		if ok {
			if pred, err := buildArrayValueConditionPredicate(typ, v.(string)); err == nil {
				return pred, nil
			} else {
				return nil, err
			}
		}
	}
	return nil, errors.Errorf("unknown condition: %v", condition)
}

func buildArrayValuePredicate(condition orderedmap.OrderedMap, extr extractor.Extractor, name string) (predicate.Predicate, error) {
	if arrayCond, err := buildArrayValueCondition(condition); err == nil {
		return predicate.ExtractedValueAccepted(extr, arrayCond), nil
	} else {
		return nil, errors.Wrapf(err, "building condition for '%s'", name)
	}
}

func buildRequestConditionPredicate(conditionOpOrName string, condition interface{}) (predicate.Predicate, error) {
	switch {
	case conditionOpOrName == "any":
		return predicate.True(), nil
	case conditionOpOrName == "and":
		if predicates, err := buildPredicatesArray(condition); err != nil {
			return nil, errors.Wrap(err, "building conditions for 'and'")
		} else {
			return predicate.And(predicates...), nil
		}
	case conditionOpOrName == "or":
		if predicates, err := buildPredicatesArray(condition); err != nil {
			return nil, errors.Wrap(err, "building conditions for 'or'")
		} else {
			return predicate.Or(predicates...), nil
		}
	case conditionOpOrName == "not":
		switch cond := condition.(type) {
		case *orderedmap.OrderedMap:
			if subpred, err := buildRequestCondition(cond); err == nil {
				return predicate.Not(subpred), nil
			} else {
				return nil, errors.Wrap(err, "building condition for 'not'")
			}
		default:
			return nil, errors.Errorf("unexpected condition element: %v", cond)
		}
	case conditionOpOrName == "path":
		return buildStringValuePredicate(condition, extractor.ExtractPath(), "path")
	case conditionOpOrName == "host":
		return buildStringValuePredicate(condition, extractor.ExtractHost(), "host")
	case conditionOpOrName == "method":
		return buildStringValuePredicate(condition, extractor.ExtractMethod(), "method")
	case strings.HasPrefix(conditionOpOrName, "query["):
		var paramName string
		fmt.Sscanf(conditionOpOrName, "query[%s]", &paramName)
		return buildStringValuePredicate(condition, extractor.ExtractQueryParameter(paramName), fmt.Sprintf("query[%s]", paramName))
	case strings.HasPrefix(conditionOpOrName, "header["):
		var headerName string
		fmt.Sscanf(conditionOpOrName, "header[%s]", &headerName)
		headerName = http.CanonicalHeaderKey(headerName)
		return buildStringValuePredicate(condition, extractor.ExtractHeader(headerName), fmt.Sprintf("query[%s]", headerName))
	default:
		return buildStringValuePredicate(condition, extractor.ExtractQueryParameter(conditionOpOrName), fmt.Sprintf("query[%s]", conditionOpOrName))
	}
}

func buildRequestCondition(reqCond *orderedmap.OrderedMap) (predicate.Predicate, error) {
	preds := make([]predicate.Predicate, 0, len(reqCond.Keys()))
	for _, conditionOpOrName := range reqCond.Keys() {
		if condition, ok := reqCond.Get(conditionOpOrName); ok {
			if pred, err := buildRequestConditionPredicate(conditionOpOrName, condition); err != nil {
				return nil, err
			} else {
				preds = append(preds, pred)
			}
		} else {
			return nil, errors.New("no content for condition")
		}
	}
	if len(preds) == 1 {
		return preds[0], nil
	} else if len(preds) > 1 {
		return predicate.And(preds...), nil
	} else {
		return nil, errors.New("no content for request condition")
	}
}

func buildTokenPredicatesArray(_conditions interface{}) ([]predicate.Predicate, error) {
	if conditions, ok := _conditions.([]interface{}); ok {
		predicates := make([]predicate.Predicate, len(conditions))
		for c, cnd := range conditions {
			switch sub := cnd.(type) {
			case orderedmap.OrderedMap:
				var err error
				if predicates[c], err = buildTokenCondition(&sub); err != nil {
					return nil, errors.Wrap(err, "error parsing request condition")
				}
			default:
				return nil, errors.Errorf("unexpected condition element: %+v", cnd)
			}
		}
		return predicates, nil
	} else {
		return nil, errors.Errorf("unexpected content for condition: %v", _conditions)
	}
}

func claimExtractor(claim string) extractor.Extractor {
	return extractor.ExtractorFunc(func(t interface{}) interface{} {
		return t.(*token.Token).Claims[claim]
	})
}

func stringOrStringArrayToArrayExtractor(delegate extractor.Extractor) extractor.Extractor {
	return extractor.ExtractorFunc(func(v interface{}) interface{} {
		switch v := delegate.Extract(v).(type) {
		case string:
			return strings.Split(v, " ")
		case []string:
			return v
		case []interface{}:
			arr := make([]string, 0, len(v))
			for _, s := range v {
				arr = append(arr, s.(string))
			}
			return arr
		default:
			panic(fmt.Sprintf("unexpected type %T, expected a string, []string, or []interface{}", v))
		}
	})
}

func containsPredicate(cmpValue string) predicate.Predicate {
	return predicate.PredicateFunc(func(value interface{}) bool {
		switch v := value.(type) {
		case []string:
			for _, c := range v {
				if c == cmpValue {
					return true
				}
			}
		case []interface{}:
			for _, c := range v {
				if c.(string) == cmpValue {
					return true
				}
			}
		}
		return false
	})
}

// must be alphebetical
var stringOrArrayClaims = []string{"aud", "scope"}

// Used to add claims that can be either single strings, arrays of strings, or a space separated string
func RegisterStringOrArrayClaim(claim string) {
	if x := sort.Search(len(stringOrArrayClaims), searchFn(claim));
		x < len(stringOrArrayClaims) && stringOrArrayClaims[x] != claim {
		stringOrArrayClaims = append(stringOrArrayClaims, "")
		copy(stringOrArrayClaims[x+1:], stringOrArrayClaims[x:])
		stringOrArrayClaims[x] = claim
	}
}

func searchFn(claim string) func(i int) bool {
	return func(i int) bool {
		return strings.Compare(stringOrArrayClaims[i], claim) >= 0
	}
}

func IsStringOrArrayClaim(claim string) bool {
	x := sort.Search(len(stringOrArrayClaims), searchFn(claim))
	return x < len(stringOrArrayClaims) && stringOrArrayClaims[x] == claim
}

func buildTokenConditionPredicate(conditionOpOrName string, condition interface{}) (predicate.Predicate, error) {
	switch {
	case conditionOpOrName == "allow":
		if allow, ok := condition.(bool); ok {
			if allow {
				return predicate.True(), nil
			} else {
				return predicate.False(), nil
			}
		}
	case conditionOpOrName == "and":
		if predicates, err := buildTokenPredicatesArray(condition); err != nil {
			return nil, errors.Wrap(err, "building conditions for 'and'")
		} else {
			return predicate.And(predicates...), nil
		}
	case conditionOpOrName == "or":
		if predicates, err := buildTokenPredicatesArray(condition); err != nil {
			return nil, errors.Wrap(err, "building conditions for 'or'")
		} else {
			return predicate.And(predicates...), nil
		}
	case conditionOpOrName == "not":
		switch cond := condition.(type) {
		case *orderedmap.OrderedMap:
			if subpred, err := buildTokenCondition(cond); err == nil {
				return predicate.Not(subpred), nil
			} else {
				return nil, errors.Wrap(err, "building condition for 'not'")
			}
		default:
			return nil, errors.Errorf("unexpected condition element: %v", cond)
		}
	default:
		if IsStringOrArrayClaim(conditionOpOrName) {
			switch cond := condition.(type) {
			case string:
				return predicate.ExtractedValueAccepted(stringOrStringArrayToArrayExtractor(claimExtractor(conditionOpOrName)), containsPredicate(cond)), nil
			case orderedmap.OrderedMap:
				return buildArrayValuePredicate(cond, claimExtractor(conditionOpOrName), conditionOpOrName)
			}
		} else {
			switch cond := condition.(type) {
			case string:
				return predicate.ExtractedValueAccepted(claimExtractor(conditionOpOrName), predicate.StringEquals(cond)), nil
			case orderedmap.OrderedMap:
				return buildStringValuePredicate(cond, claimExtractor(conditionOpOrName), conditionOpOrName)
			}
		}
	}
	return nil, nil
}

func buildTokenCondition(tokCond *orderedmap.OrderedMap) (predicate.Predicate, error) {
	preds := make([]predicate.Predicate, 0, len(tokCond.Keys()))
	for _, conditionOpOrName := range tokCond.Keys() {
		if condition, ok := tokCond.Get(conditionOpOrName); ok {
			if pred, err := buildTokenConditionPredicate(conditionOpOrName, condition); err != nil {
				return nil, err
			} else {
				preds = append(preds, pred)
			}
		} else {
			return nil, errors.Errorf("no content for '%s' condition", conditionOpOrName)
		}
	}
	if len(preds) == 1 {
		return preds[0], nil
	} else if len(preds) > 1 {
		return predicate.And(preds...), nil
	} else {
		return nil, errors.New("no content for token condition")
	}
}

func buildAccessRules(introspectors map[string]token.TokenIntrospector, accessRules []*config.OAuth2AccessRule) ([]*oauth2.AccessRule, error) {
	oauthAccessRules := make([]*oauth2.AccessRule, 0, len(accessRules))
	defaultIntrospector := introspectors["default"]
	fmt.Printf("defaultIntrospector = %v\nintrospectors = %v\n", defaultIntrospector, introspectors)
	for _, accessRule := range accessRules {
		introspector := defaultIntrospector
		if len(accessRule.TokenIntrospector) > 0 {
			ti, ok := introspectors[accessRule.TokenIntrospector]
			if ok {
				introspector = ti
			} else {
				return nil, errors.Errorf("error parsing access rule: named token introspector is not found")
			}
		}
		if introspector == nil {
			return nil, errors.Errorf("error parsing access rule: TokenIntrospector is required or a 'default' introspector must be provided")
		}
		if reqCond, err := buildRequestCondition(accessRule.RequestCondition); err != nil {
			return nil, errors.Wrapf(err, "error creating request condition: %v", accessRule.RequestCondition)
		} else {
			if tokCond, err := buildTokenCondition(accessRule.TokenCondition); err != nil {
				return nil, errors.Wrapf(err, "error creating token condition: %v", accessRule.TokenCondition)
			} else {
				oauthAccessRules = append(oauthAccessRules, &oauth2.AccessRule{
					RequestCondition:  reqCond,
					TokenIntrospector: introspector,
					TokenCondition:    tokCond,
				})
			}
		}
	}
	return oauthAccessRules, nil
}

func buildOAuth2Config(authConfig *config.OAuth2Auth) (*oauth2.OAuth2Config, error) {
	if introspectors, err := buildTokenIntrospectors(authConfig.TokenIntrospectors); err == nil {
		fmt.Printf("introspectors: %v\n", introspectors)
		if accessRules, err := buildAccessRules(introspectors, authConfig.AccessRules); err == nil {
			fmt.Printf("accessRules: %v\n", accessRules)
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
		return nil, err
	} else {
		fmt.Printf("oAuth2Config = %#v\n", oAuth2Config)
		return oauth2.NewOAuth2Provider(oAuth2Config).Handler(next)
	}
}
