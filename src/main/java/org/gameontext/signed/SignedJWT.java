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

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Common class for handling JSON Web Tokens
 *
 * @author marknsweep
 *
 */

public class SignedJWT {
    private final AuthenticationState state;
    private FailureCode code = FailureCode.NONE;

    private String token = null;
    private JWTCallerPrincipal jwtcp = null;

    public SignedJWT(Certificate cert, String... sources) {
        state = processSources(cert.getPublicKey(), sources);
    }

    public SignedJWT(PublicKey key, String... sources) {
        state = processSources(key, sources);
    }

    // the authentication steps that are performed on an incoming request
    public enum AuthenticationState {
        PASSED,
        ACCESS_DENIED // end state
    }

    public enum FailureCode {
        NONE("ok"),
        MISSING_JWT("JWT not found in header or query string"),
        BAD_SIGNATURE("Bad signature."),
        EXPIRED("Expired token");

        final String reason;

        FailureCode(String reason) {
            this.reason = reason;
        }

        public String getReason() {
            return reason;
        }
    }

    private AuthenticationState processSources(PublicKey key, String[] sources) {
        AuthenticationState state = AuthenticationState.ACCESS_DENIED; // default

        //find the first non-empty source, assign to token
        for(int i = 0; i < sources.length && ((token == null) || token.isEmpty()); token = sources[i++]);

        if ((token == null) || token.isEmpty()) {
            // we couldn't find a non-empty token. No dice.
            code = FailureCode.MISSING_JWT;
        } else {
            try {
                JWTAuthContextInfo ctx = new JWTAuthContextInfo(key, "test");
                ctx.setIssuedBy(null);
                ctx.setRequiredClaims(Set.of("sub","aud","name","id","exp","iat"));

                JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
                jwtcp = factory.parse(token, ctx);

                state = AuthenticationState.PASSED;
                code = FailureCode.NONE;
            } catch (ParseException e) {
                code = FailureCode.BAD_SIGNATURE;
                SignedRequestFeature.writeLog(Level.WARNING, this, "JWT failed validation {0}. {1}", e.getMessage(), token);
            }
        }

        return state;
    }

    public boolean isValid() {
        return state == AuthenticationState.PASSED;
    }

    public AuthenticationState getState() {
        return state;
    }

    public FailureCode getCode() {
        return code;
    }

    public String getToken() {
        return token;
    }

    public Object getClaim(String claim) {
        String json = new String(Base64.getUrlDecoder().decode(jwtcp.getClaim("raw_token").toString().split("\\.")[1]), StandardCharsets.UTF_8);
        try {
            JwtClaims jc = JwtClaims.parse(json);

            return jc.getClaimValue(claim);

        } catch (InvalidJwtException e) {
            return null;
        }
    }

    public Collection<String> getClaimNames(){
        String json = new String(Base64.getUrlDecoder().decode(jwtcp.getClaim("raw_token").toString().split("\\.")[1]), StandardCharsets.UTF_8);
        try {
            JwtClaims jc = JwtClaims.parse(json);

            return jc.getClaimNames();

        } catch (InvalidJwtException e) {
            return Collections.emptySet();
        }
    }

}
