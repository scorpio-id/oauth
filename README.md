# Oauth2: The Industry Standard for user authorization
## What is Oauth2?

Oauth2, or Open Authorization 2.0, is a security standard for delegated authorization between a resource owner, or user, and an application, or client.

Both Oauth1, the predecessor to Oauth2, and Oauth2 were created and standardized from the combined concepts of many different industry authorization protocols. The best aspects of each of the different protocols were used to developed Oauth.

## What problems does Oauth2 address and solve, and why is it used?

Oauth enables the user to grant access to their resources without sharing their identity or login credentials. Oauth2 addresses the antiquated methods of authorization through plain text username and password exchange and storage. 

## Roles, Concepts, and Terminology

The framework of Oauth2 has various roles, concepts, and components at play in order to enable secure delegated authorization. These include: 

| Term | Description | 
| ---- | ----------- | 
|Resource Owner | end-user, capable of granting access to their protected resource | 







-Resource Ownner: The User

-Client: The application seeking the data.

-Authorization Server: The system used to authorize permission.

-Resource Server: AKA API; the system that holds the data the Client wants access to.

-Scopes: The specific reason stated for wanting access to resources by the client.

-Authorization Code Grant: Proof that the user has given the client permission to gain access to the data. 

-Access Token: Typically seen in a JWT format, or Json Web Token format, this is the key to the data that is stored in the resource server. The Authorization Code Grant enables the client to obtain a JWT.



# JWKS (JSON Web Key Set)

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

## Authorizatiion Code Grant 
More info on Authorization Code Grant and its standards can be found in the RFC: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1

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






