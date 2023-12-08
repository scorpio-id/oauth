JWKS
RFC: https://datatracker.ietf.org/doc/html/rfc7517#section-5

GET /jwks 

HTTP 200 OK
Content-Type: application/json

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

Client Credentials
RFC: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4

POST /token
Content-Type: application/x-www-form-urlencoded

| Form Parameter | Value | Description | 
| -------------- | ----- | ----------- | 
| grant_type     | client_credentials |  Required Per RFC6749 |
| client_id      | string             |  Client Identifier    | 








# Oauth2: The Industry Standard for user authorization
## What is Oauth2?

Oauth2, or Open Authorization 2.0, is a security standard for delegated authorization between a resource owner, or user, and an application, or client.

Both Oauth1, the predecessor to Oauth2, and Oauth2 were created and standardized from the combined concepts of many different industry authorization protocols. The best aspects of each of the different protocols were used to developed Oauth.

## What problems does Oauth2 address and solve, and why is it used?

Oauth enables the user to grant access to their resources without sharing their identity or login credentials. Oauth2 addresses the antiquated methods of authorization through plain text username and password exchange and storage. 

## Roles, Concepts, and Terminology

The framework of Oauth2 has various roles, concepts, and components at play in order to enable secure delegated authorization. These include: 

-Resource Ownner: The User

-Client: The application seeking the data.

-Authorization Server: The system used to authorize permission.

-Resource Server: AKA API; the system that holds the data the Client wants access to.

-Scopes: The specific reason stated for wanting access to resources by the client.

-Authorization Code Grant: Proof that the user has given the client permission to gain access to the data. 

-Access Token: Typically seen in a JWT format, or Json Web Token format, this is the key to the data that is stored in the resource server. The Authorization Code Grant enables the client to obtain a JWT.

## Basic Authorization Code Flow of Oauth2

At the basic level before using Oauth2, the client must obtain its own credentials that include a client ID and a client secret. The ID will be shared but the secret is to not be shared. This will enable the client to authenticate itself when requesting an access token in the later part of the flow. 

A basic flow in Oauth2 involves the authorization code grant. First, the resource owner initiates the flow by visiting the client site and redirects to the authorization server. A redirect URI is provided in this process. The resource owner logs into the authorization server and then redirects back to the redirect URI with the authorization code. The client then presents the authorization code to the authorization server in exchange for an access token. If an access token is granted, the client then contacts the resource server with a request. The request contains the access token granted by the authorization server, allowing the client to gain access to the resource owner's data. 

The access token is typically seen in a JSON Web Token format. This format involves symetric and asymetric encryption, allowing the token to be transported over the web securely






