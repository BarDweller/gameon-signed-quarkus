/*******************************************************************************
 * Copyright (c) 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/
package org.gameontext.signed;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.Base64.Decoder;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.arc.Unremovable;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

@ApplicationScoped
@Unremovable
public class SignedJWTValidator {


    /** SignedJWT Signing key */
    protected PrivateKey signingKey = null;
    protected Optional<String> pemKey = null;

    /** SignedJWT verification Certificate */
    protected Certificate validationCert = null;
    protected String pemCert;

    /**
     * Obtain the key we'll use to sign the jwts we issue.
    */
    @PostConstruct
    protected void readKeyAndCert() {
        try {
            if(null==pemKey || pemKey.equals("x")){
                pemKey = ConfigProvider.getConfig().getOptionalValue("JWT_PRIVATE_KEY", String.class);
            }

            if(pemKey.isPresent()){                    
                String stripped = pemKey.get().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "");
            
                Decoder decoder = Base64.getDecoder();
                byte[] decoded = decoder.decode(stripped);

                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                signingKey = kf.generatePrivate(keySpec);
            }

            if(null==pemCert || pemCert.equals("x")){
                pemCert = ConfigProvider.getConfig().getValue("JWT_PUBLIC_CERT", String.class);
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            validationCert = factory.generateCertificate(new ByteArrayInputStream(pemCert.getBytes()));

        } catch (NoSuchAlgorithmException |
                InvalidKeySpecException e) {
            throw new IllegalStateException("Unable to process private key", e);
        } catch (CertificateException e) {
            throw new IllegalStateException("Unable to process public cert", e);
        }
    }           

    public SignedJWT getJWT(String jwtParam) {
        return new SignedJWT(validationCert, jwtParam);
    }

    public String clientToServer(SignedJWT jwt) {
        if( signingKey == null){
            throw new IllegalStateException("Cannot convert client token to server token due to missing private key");
        }
        if ( jwt.isValid() ) {

            JwtClaimsBuilder claimsBuilder = Jwt.claims();

            for(String claimName : jwt.getClaimNames() ){
                claimsBuilder.claim(claimName, jwt.getClaim(claimName));
            }

            claimsBuilder.audience("server");

            String newJwt = claimsBuilder.jws().sign(signingKey);

            return newJwt;
        }

        return null;
    }
}
