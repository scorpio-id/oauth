# Oauth2: The Industry Standard for user authorization
## What is Oauth2?

Oauth2, or Open Authorization 2.0, is a security standard for delegated authorization between a resource owner, or user, and an application, or client.

Both Oauth1, the predecessor to Oauth2, and Oauth2 were created and standardized from the combined concepts of many different industry authorization protocols. The best aspects of each of the different protocols were used to developed Oauth.

## What problems does Oauth2 address and solve, and why is it used?

Oauth enables the user to grant access to their resources without sharing their identity or login credentials. Oauth2 addresses the antiquated methods of authorization through plain text username and password exchange and storage. 

## Roles, Concepts, and Terminology

More info on Oauth2 roles, concepts, and terminology can be found in the RFC: https://datatracker.ietf.org/doc/html/rfc6749#section-1 

The framework of Oauth2 has various roles, concepts, and components at play in order to enable secure delegated authorization. These include: 

| Term | Description | 
| ---- | ----------- | 
| Resource Owner | end-user, capable of granting access to their protected resource | 
| Client | The application (server, desktop, etc.) requesting access to the user's protected resource with its authorization |
| Authorization Server | The server responsible for authorizing permission for the client in the form of access token grants | 
| Resource Server | The server hosting the end-user's protected resources. Accepts and responds to request using access tokens |
| Scopes | The specific reason for desired access by the client | 
| Access Token | Typically seen in JWT format (JSON Web Token), the Access Token is used by the client to access the user's data stored in the resource server | 

# JWKS (JSON Web Key Set)

JWKS, or JSON Web Key Set, is a set of keys containing the public keys used to identify any JSON Web Token (JWT) that is issued by the authorization server. Signed using the RS256 algorithm.

More info on JWKS and its standards can be found in the RFC: https://datatracker.ietf.org/doc/html/rfc7517#section-5

### Request
```http
GET /jwks 
```
### Response
```http
HTTP 200 OK
Content-Type: application/json
```

```json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "b83e7eda-d7fa-4c81-8ddf-7bf4480baa35",
            "alg": "RS256",
            "n": "6zM13c6IZlvN3 ... ug64DCTRhWlHcBiCq71CMyFw",
            "e": "AQAB"
        }
    ]
}
```

# Grants/Flows
## Client Credentials
The client credentials grant type is a grant flow where the client may request an access token using only their set of credentials. This is typically in the form of a client_id. Without a client_id, an access token will not granted by the authorization server.

More info on Client Credentials and its standards can be found in the RFC: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4

### Request
```http
POST /token
Content-Type: application/x-www-form-urlencoded
```
### Parameters
| Form Parameter | Value | Description | 
| -------------- | ----- | ----------- | 
| grant_type     | client_credentials |  Required RFC6749 |
| client_id      | string             |  Client Identifier    | 

### Response
```http
HTTP 200 OK
Content-Type: application/json
```

```json
{
    "access_token": "eyJhbGciOiJSUz ... ImtpZ8nBKeziYH0f71w",
    "token_type": "bearer",
    "expires_in": 3600
}
```

## Authorization Code Grant 
The authorization code grant is a flow in which the client application will request an authorization code from the authorization server and use the given code along with other parameters to receive an access token. The access token will be used to access the data in the user's resource server.

More info on Authorization Code Grant and its standards can be found in the RFC: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1

### Request
```http
GET /authorize
Content-Type: application/x-www-form-urlencoded
```

### Parameters
| Form Parameter | Value | Description | 
| -------------- | ----- | ----------- | 
| response_type  | code  | Required RFC6749 |
| client_id      | string | Client Identifier |
| redirect_uri   | string | URI Location of Recipient for Authorization Code |

### Response 
```http
HTTP 302 Found
Location: https://my.redirect/uri?code=cc496de4-9616-11ee-b9d1-0242ac120002 
```

### Request
```http
POST /jwt 
Content-Type: application/x-www-form-urlencoded
```

### Parameters
| Form Parameter | Value | Description | 
| -------------- | ----- | ----------- | 
| grant_type     | authorization_code  | Required RFC6749 |
| code           | uuid | Authorization Code Sent to Redirect URI |
| redirect_uri   | string | Original Redirect URI |
| client_id      | string | Client Identifier |

### Response
```http
HTTP 200 OK
Content-Type: application/json
```

```json
{
    "access_token": "eyJhbGciOiJSUz ... ImtpZ8nBKeziYH0f71w",
    "token_type": "bearer",
    "expires_in": 3600
}
```

### JWT.io Parameters Example

JWT.io allows you to decode, verify, and generate a JWT, or JSON Web Token. For the JWT template to paste your own access tokens into, visit: https://jwt.io/ 

This JWT decoder provides you with the following parameters:

| Form Parameter | Value | Description | 
| -------------- | ----- | ----------- | 
| alg | RS256 | Asymetric Encryption Algorithm using SHA256 hashing |
| kid | e939...aba | Key ID |
| typ | JWT | Identifies the type of token pasted |
| aud | string | Audience-who or what the token is intended for | 
| exp | 1702343792 | Expiration time (seconds since Unix epoch) |
| iat | 1702340192 | Issued at (seconds since Unix epoch) |
| iss | http://localhost... | Issuer (who created and signed token) | 
| jti | 8fed... 08a2 | JWT ID (unique identifier for the token) | 
| nbf | 1702340164 | not valid before (seconds since Unix epoch) |
| sub | string | subject | (whom the token refers to) |

