# Signed: A library for processing signed JWTs and HMACs in Game On

[![Release](https://jitpack.io/v/bardweller/gameon-signed-quarkus.svg)](https://jitpack.io/#bardweller/gameon-signed-quarkus)

For client/server consistency, we've created some common libraries to help with
signing and verifying requests that use JWTs or HMACs.

This version of [gameontext/signed](https://github.com/gameontext/signed) uses SmallRye JWT rather than JJWT. 
The intent is that this version of signed is better able to tolerate being built into Quarkus Native Apps.

Additionally, this version requires Java 11. I mean.. Java 8 was a long time ago (in a galaxy far far away).

## Using the library in your Java projects

We use jitpack to build this library, which means you can direct maven or gradle directly to our github releases to satisfy dependencies.

1. include jitpack.io in your list of repositories:
  * In maven:
  ```
    <repositories>
      <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
      </repository>
    </repositories>
  ```
  * In gradle:
  ```
    repositories {
      maven { url "https://jitpack.io" }
    }
  ```
2. Include version of the library in your dependencies:
  * In maven:
  ```
    <dependency>
      <groupId>com.github.bardweller</groupId>
      <artifactId>gameon-signed-quarkus</artifactId>
      <version>master-SNAPSHOT</version>
    </dependency> 
  ```
  * In gradle:
  ```
    dependencies {
	    compile 'com.github.bardweller:gameon-signed-quarkus:master-SNAPSHOT'
    }
  ```
3. Use SignedRequest* utilities to handle request signing

  * SignedRequestFilter with JAX-RS 2.0 client:
  ```
    Client client = ClientBuilder.newClient().register(JsonProvider.class);

    SignedClientRequestFilter apikeyFilter = new SignedClientRequestFilter(userid, secret);
    client.register(apikeyFilter);
  ```

  * Room-side of WebSocket Handshake via ServerEndpointConfig.Configurator
  ```
        public void modifyHandshake(ServerEndpointConfig sec, HandshakeRequest request, HandshakeResponse response) {
            super.modifyHandshake(sec, request, response);

            if ( token == null || token.isEmpty() ) {
                Log.log(Level.FINEST, this, "No token set for room, skipping validation");
            } else {
                Log.log(Level.FINEST, this, "Validating WS handshake");
                SignedRequestHmac wsHmac = new SignedRequestHmac("", token, "", request.getRequestURI().getRawPath());

                try {
                    wsHmac.checkHeaders(new SignedRequestMap.MLS_StringMap(request.getHeaders()))
                            .verifyFullSignature()
                            .wsResignRequest(new SignedRequestMap.MLS_StringMap(response.getHeaders()));

                    Log.log(Level.INFO, this, "validated and resigned", wsHmac);
                } catch(Exception e) {
                    Log.log(Level.WARNING, this, "Failed to validate HMAC, unable to establish connection", e);

                    response.getHeaders().replace(HandshakeResponse.SEC_WEBSOCKET_ACCEPT, Collections.emptyList());
                }
            }
        }
  ```
