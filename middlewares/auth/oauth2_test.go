package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/containous/traefik/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This is a TEST key, this private key is not used to secure any actual prod or LLC environment it is matched with the
// public key in the test config below.  -- DHP 2019/02/26
var testKeyText = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMEiE84uXbDUMnZhfZ/zlu8z6/IXxZN9g57ylylRqzooUbkV
Fqgx2E/hqCrzdkiQ08VDIDhuFJ9sYJEmbRNtbxVftDuIKefTmDu576P6j3ob6F3I
Szbosr5Wyo6ixXPbJpYpurmMF0nFgIcfkxBR3iBmmNlItP5PlMW90oi/+gVYHiHq
1Mc77jCahcK2WDLYeNpU8puXGwH4udIIK14TPWmUHWb1IEBTAXr+c+Qpm3vC70zR
vdygzWMLtO5grSzDngCIZCuieMQq8v415ToAh6zBiH4YhdXuuZ5iT9R2z1ZjhtkW
g5cmXNZ1bXMnc86cbOoSlOmrtpc///SRcGRbMwIDAQABAoIBAGtj57j3acAP3ugO
I5Dv/plHJTkKmYLAvn5ZT81JuSz8Ox91o6ptzbtcg2BKxwWEHJrb2K7L3kCigk6H
UHyqhDvDgsOyru0c0cN1RBjliekII1yn1prRqeTr+mr3CeoX89S0CEF/RMzslp6k
7FeBbvTchIZoFnkOMZfacQIFdwGOSGWKNMiim/jMdCSD8EheET6oizG+LeLmexfZ
4yAvtb/OF3KKO2VobpBznkCQWDoIlVOD3KreBjDKtyVpUt/HptabauuZKM3gVyvn
QLZ8qW1JYyFCN6xeB2ZdHgvBgQ7MF8wkmn3bPRJ3ERtzLJBRTKKl6XVu/RdCm/Gg
S0zwx1ECgYEA5w4rBCGlmeTI363uNKcY2n/hxqxHhAWHAG/1hGRlG7B5vP+BSQid
88nXL9XVPjzj2MwOrQXBirCMbwU3wxiiXJtYw+Ngur45ILiQbCRY9XPrSLcbTXzh
B3A72f5Ta1QmfrQLT3C/u80NqL/mx6GEHG4s28YmUExqZpa2IdAqC+UCgYEAzLNQ
wwJ84EGp/CFV1qxy48Wyc5EPu3+vKL0zXDwnccf35WnFRIyznb/wKFFSo/U6d7ES
Wm+JRwRUkBQR5qzkI9jF8c3Rt39X/+QSOkq96Rmfrg0XvEYBT4BMjfv/wX1UbzRg
8jbdGGb6cBwzmaHW0z7YqKOdxiujjA9P9MWhyTcCgYB3RSMDYPMA+86NWFVMLK1x
rO25BplsFwZXPXP5QXHH11MgMqxkLOSMQbao5LLNC9V5xewVeJEtrHDxpjngpci6
ER7DD46RFzyaHWu/xwt8uLfNs2eOmlX25wKeRuB82NV+NiZYfZUbtn/Eijrw9fki
S+UwFZsVfDy4dDfUQIZT2QKBgD5Fmp8IhbavIygZeASLh5P1E3mGurN+f2m0TQiV
ICbD/4zh5WoaJ5YoysVpH+vS8UtyKbQrVCavkY4XHO8Az5J8IpOR2mepLLsixczH
6ggcjHAleYAEB+gIjsFu1Pomx2XhGFD3EcGXqj4qxiPJkRHIf56lz5x2sBUun1NG
QBZ3AoGAZ09f0EWGGSn+Ej+MpVpIzhEiqWc9vYuLDadXFptma0msH6NBPbngA4Lz
FGGXxSLGITMQ+9GsRzUd2D/GwJgK7SSkJiLccx1dJtaI3zybGkJDUpIvLhljh5wF
wYMPGgxii0sXCXdvKcR2sMdacl6QPreaKSw+x5EMCDuAmdSGNFg=
-----END RSA PRIVATE KEY-----
`

var test = `
{
	"accessRules": [
		{
			"requestCondition": {
				"and": [
					{
						"path": {
							"matches": "/book(/[0-9]+)?"
						}
					},
					{
						"or": [
							{
								"method": {
									"equals": "DELETE"
								}
							},
							{
								"method": {
									"equals": "PUT"
								}
							},
							{
								"method": {
									"equals": "POST"
								}
							}
						]
					}
				]
			},
			"tokenIntrospector": "default",
			"tokenCondition": {
				"and": [
					{
						"scope": {
							"contains": "write"
						}
					},
					{
						"iss": {
							"equals": "usom-uaa"
						}
					}
				]
			}
		},
		{
			"requestCondition": {
				"path": {
					"matches": "/book(/[0-9]+)?"
				},
				"method": {
					"equals": "GET"
				}
			},
			"tokenCondition": {
				"scope": {
					"contains": "read"
				},
				"iss": {
					"equals": "usom-uaa"
				}
			}
		},
		{
			"requestCondition": {
				"path": {
					"equals": "/env"
				}
			},
			"tokenCondition": {
				"allow": true
			}
		},
		{
			"requestCondition": {
				"any": true
			},
			"tokenCondition": {
				"allow": false
			}
		}
	],
	"realm": "usom_uaa",
	"tokenIntrospectors": {
		"jwt": {
			"type": "jwt",
			"publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMEiE84uXbDUMnZhfZ/z\nlu8z6/IXxZN9g57ylylRqzooUbkVFqgx2E/hqCrzdkiQ08VDIDhuFJ9sYJEmbRNt\nbxVftDuIKefTmDu576P6j3ob6F3ISzbosr5Wyo6ixXPbJpYpurmMF0nFgIcfkxBR\n3iBmmNlItP5PlMW90oi/+gVYHiHq1Mc77jCahcK2WDLYeNpU8puXGwH4udIIK14T\nPWmUHWb1IEBTAXr+c+Qpm3vC70zRvdygzWMLtO5grSzDngCIZCuieMQq8v415ToA\nh6zBiH4YhdXuuZ5iT9R2z1ZjhtkWg5cmXNZ1bXMnc86cbOoSlOmrtpc///SRcGRb\nMwIDAQAB\n-----END PUBLIC KEY-----"
		},
		"rfc7662": {
			"type": "rfc7662",
			"endpoint": "http://localhost:8081/oauth/check"
		},
		"default": {
			"type": "multi",
			"introspectors": [
				{
					"ref": "jwt"
				},
				{
					"ref": "rfc7662"
				}
			]
		}
	}
}
`
var testKey *rsa.PrivateKey
var cfg config.OAuth2Auth

func init() {
	b, _ := pem.Decode([]byte(testKeyText))
	if b == nil {
		panic("could not decode pem")
	}
	var err error
	if testKey, err = x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
		panic(err)
	}
	if err = json.Unmarshal([]byte(test), &cfg); err != nil {
		panic(err)
	}
	fmt.Printf("OAuth2Auth: %v\n", &cfg)
}

func TestNewOAuth2(t *testing.T) {
	now := time.Now()
	readWriteClaims := jwt.MapClaims{
		"active": true,
		"scope":  []string{"read", "write"},
		"iss":    "usom-uaa",
		"aud":    "usom-router",
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iat":    now.Unix(),
	}
	readOnlyClaims := jwt.MapClaims{
		"active": true,
		"iss":    "usom-uaa",
		"scope":  []string{"read"},
		"aud":    "usom-router",
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iat":    now.Unix(),
	}
	readOnlyJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, readOnlyClaims)
	testReadOnlyToken, err := readOnlyJWT.SignedString(testKey)
	assert.NoError(t, err)

	notActiveCliams := jwt.MapClaims{
		"active": false,
	}

	testReadWriteToken := uuid.NewV4().String()
	testInactiveToken := uuid.NewV4().String()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/check" && r.Method == "POST" {
			r.ParseForm()
			tokenStr := r.Form["token"][0]
			w.WriteHeader(200)
			jw := json.NewEncoder(w)
			if tokenStr == testReadWriteToken {
				jw.Encode(readWriteClaims)
			} else {
				jw.Encode(notActiveCliams)
			}
		}
	}))
	defer testServer.Close()
	cfg.TokenIntrospectors["rfc7662"].Endpoint = testServer.URL + "/oauth/check"

	ctx := context.TODO()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	authHandler, err := NewOAuth2(ctx, next, &cfg, "test")
	if assert.NoError(t, err) && assert.NotNil(t, authHandler) {
		t.Logf("authHandler = %s", authHandler)
		// ReadOnly:
		// GET List:
		testWriter := httptest.NewRecorder()
		testRequest := httptest.NewRequest("GET", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadOnlyToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result := testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// GET Single:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("GET", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadOnlyToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// POST:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("POST", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadOnlyToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// PUT:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("PUT", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadOnlyToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// DELETE:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("DELETE", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadOnlyToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// ReadWrite:
		// GET List:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("GET", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadWriteToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// GET Single:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("GET", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadWriteToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// POST:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("POST", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadWriteToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// PUT:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("PUT", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadWriteToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// DELETE:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("DELETE", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testReadWriteToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 200, result.StatusCode)

		// Inactive:
		// GET List:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("GET", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testInactiveToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// GET Single:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("GET", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testInactiveToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// POST:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("POST", "http://localhost/book", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testInactiveToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// PUT:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("PUT", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testInactiveToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)

		// DELETE:
		testWriter = httptest.NewRecorder()
		testRequest = httptest.NewRequest("DELETE", "http://localhost/book/1", nil)
		testRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testInactiveToken))
		authHandler.ServeHTTP(testWriter, testRequest)
		result = testWriter.Result()
		assert.Equal(t, 401, result.StatusCode)
	}
}

func TestIsStringOrArrayClaim(t *testing.T) {
	assert.True(t, IsStringOrArrayClaim("scope"))
	assert.True(t, IsStringOrArrayClaim("aud"))
	assert.False(t, IsStringOrArrayClaim("iss"))
}

func TestRegisterStringOrArrayClaim(t *testing.T) {
	RegisterStringOrArrayClaim("roles")
	TestIsStringOrArrayClaim(t)
	assert.True(t,IsStringOrArrayClaim("roles"))
}
