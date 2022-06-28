/*******************************************************************************
 * Copyright (c) 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.gameontext.signed;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.stream.Collectors;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

/**
 * The server-side of signed request processing (the Map service uses this, for example).
 *
 * Note you won't find many direct references to this class, because it the {@link SignedRequestFeature}
 * registers this filter for methods using the {@link SignedRequest} annotation.
 *
 * @see SignedRequestFeature#configure(javax.ws.rs.container.ResourceInfo, javax.ws.rs.core.FeatureContext)
 */
public class SignedContainerRequestFilter implements ContainerRequestFilter {

    private final SignedRequestSecretProvider playerClient;
    private final SignedRequestTimedCache timedCache;

    public SignedContainerRequestFilter(SignedRequestSecretProvider playerClient, SignedRequestTimedCache timedCache) {
        this.playerClient = playerClient;
        this.timedCache = timedCache;

        if ( playerClient == null || timedCache == null ) {
            SignedLogger.writeLog(Level.SEVERE, this,
                    "Required resources are not available: playerClient={0}, timedCache={1}",
                    playerClient, timedCache);
            throw new IllegalStateException("Required resources are not available");
        }
    }

    /**
     * Reads the headers/method of the inbound request. If the request is signed, we will perform the steps
     * to validate the signature (unless there is a message body, in which case we save the {@link SignedRequestHmac}
     * and finish verifying the signature after the message body has been read).
     *
     * A signature is not required for GET requests. If a GET request is signed, we will validate the signature.
     * This can be used, for example, to share more information with the owner of a resource than you would
     * with the casual viewer.
     *
     * If a signature is present and is invalid, the request will be refused as {@link Status#FORBIDDEN}.
     *
     * @see javax.ws.rs.container.ContainerRequestFilter#filter(javax.ws.rs.container.ContainerRequestContext)
     * @see SignedReaderInterceptor
     * @see SignedRequestFeature
     * @see SignedRequestHmac
     */
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        WebApplicationException invalidHmacEx = null;
        SignedRequestHmac hmac = null;

        String userId = requestContext.getHeaderString(SignedRequestHmac.GAMEON_ID);
        String method = requestContext.getMethod();

        SignedLogger.writeLog(Level.FINEST, this, "REQUEST FILTER: USER={0}, PATH={1}, QUERY={2}, HEADERS={3}",
                userId,
                method + " "  + requestContext.getUriInfo().getAbsolutePath().getRawPath(),
                requestContext.getUriInfo().getQueryParameters(false),
                requestContext.getHeaders());

        if ( userId == null || userId.trim().isEmpty()) {
            if ( "GET".equals(method) ) {
                // no validation required for GET requests. If an ID isn't provided,
                // then we won't do validation and will just return.
                SignedLogger.writeLog(Level.FINEST, this, "FILTER: GET WITH NO ID-- NO VERIFICATION");
                return;
            } else {
                //debug empty userid header..
                if(userId!=null){
                    BufferedReader buffer = new BufferedReader(new InputStreamReader(requestContext.getEntityStream(), SignedRequestHmac.UTF8));
                    String body = buffer.lines().collect(Collectors.joining("\n"));
                    SignedLogger.writeLog(Level.FINEST,this,"BODY: "+body);
                }

                SignedLogger.writeLog(Level.FINEST, this, "FILTER: "+method+" WITH NO ID-- UNAUTHORIZED");
                // STOP!! turn this right around with the bad response
                requestContext.abortWith(Response.status(Status.FORBIDDEN).build());
                return;
            }
        }

        SignedLogger.writeLog(Level.FINEST, this, "FILTER: ID PRESENT.. VALIDATING...");

        try {
            SignedRequestMap headers = new SignedRequestMap.MVSS_StringMap(requestContext.getHeaders());
            SignedRequestMap query = new SignedRequestMap.MVSS_StringMap(requestContext.getUriInfo().getQueryParameters(false));

            String secret = playerClient.getSecretForId(userId);
            hmac = new SignedRequestHmac(userId, secret, method,
                    requestContext.getUriInfo().getAbsolutePath().getPath())
                    .checkHeaders(headers)
                    .checkDuplicate(timedCache)
                    .checkExpiry()
                    .verifyRequestHeaderHashes(headers, query);

            if ( hmac.hasRequestBody() ) {
                // set this as a property on the request context, and wait for the
                // signed request interceptor to catch the request
                // @see SignedReaderInterceptor as assigned by SignedRequestFeature
                requestContext.setProperty("SignedRequestHmac", hmac);
            } else {
                SignedLogger.writeLog(Level.FINEST, this, "FILTER: verifying hmac");
                hmac.verifyFullSignature();
                SignedLogger.writeLog(Level.FINEST, this, "FILTER: hmac verified");
            }
        } catch(WebApplicationException ex) {
            invalidHmacEx = ex;
        } catch(Exception e) {
            invalidHmacEx = new WebApplicationException("Unexpected exception validating signature", e,
                    Response.Status.INTERNAL_SERVER_ERROR);
        }

        requestContext.setProperty("player.id", userId);
        SignedLogger.writeLog(Level.FINEST, this, "FILTER: {0} {1}", invalidHmacEx, hmac);

        if ( invalidHmacEx != null ) {
            invalidHmacEx.printStackTrace();

            // STOP!! turn this right around with the bad response
            requestContext.abortWith(invalidHmacEx.getResponse());
        }
    }
}
