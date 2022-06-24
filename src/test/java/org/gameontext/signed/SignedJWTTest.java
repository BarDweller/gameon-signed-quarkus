package org.gameontext.signed;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;

import org.junit.Test;

import io.netty.util.internal.SystemPropertyUtil;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

public class SignedJWTTest {

//note this is a self signed cert and key, used for this test case.
//this is not a live credential. 

    String cert = ""+
"-----BEGIN CERTIFICATE-----\n"+
"MIIGHDCCBASgAwIBAgIULAaLxNZg7TNa0cb8X5f8ipvroMwwDQYJKoZIhvcNAQEL\n"+
"BQAwgZExFzAVBgNVBAMMDmdhbWVvbnRleHQub3JnMR4wHAYDVQQLDBVHYW1lT24g\n"+
"RGV2ZWxvcG1lbnQgQ0ExKTAnBgNVBAoMIFRoZSBGaWN0aWNpb3VzIEdhbWVPbiBD\n"+
"QSBDb21wYW55MQ4wDAYDVQQHDAVFYXJ0aDEOMAwGA1UECAwFSGFwcHkxCzAJBgNV\n"+
"BAYTAkNBMB4XDTIyMDYyMzEzNDYyN1oXDTMyMDYyMDEzNDYyN1owgZgxCzAJBgNV\n"+
"BAYTAkNBMQ4wDAYDVQQIDAVIYXBweTEOMAwGA1UEBwwFRWFydGgxJjAkBgNVBAoM\n"+
"HVRoZSBGaWN0aWNpb3VzIEdhbWVPbiBDb21wYW55MRswGQYDVQQLDBJHYW1lT24g\n"+
"QXBwbGljYXRpb24xJDAiBgNVBAMMG2dhbWVvbi4xNzIuMjAuMjU1LjcxLm5pcC5p\n"+
"bzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMevM99TP0D7qIbKgo1t\n"+
"PhQQsUzQ1nUtt0O6+TF3rao5f7lqNV3cexODb3lY4mWIbb5X+ZRpjqOuJVsjXTlt\n"+
"3WcfOo1ALPfSspEREM/5UymEhzEOEHum2kqSoqaUWkwThE9b4GABYXVLH69GvdJP\n"+
"Yj3YUlk81aX/NgQ8uJSeRllc+Jyb20MyrYRDvF7V3p8OJXcN4mTZbbrXjNwvF381\n"+
"B8U5qFEIUh+Kwxnq1vuGWBYqYMuU2EjJyfWxokpfdSpPcejxvLKvepM0yHh9YbdF\n"+
"f8KprUFtYyctrKTG6sVMVcvDgy16TDHBzRZqO1mebMs31EhbO5vp+G1FRYDEF4eZ\n"+
"N/MCZ67cHxLYGDXXvWlpWUOI/PlkgRG/JyywcocHN4web1mKX3rJdfJI7iNLSbAH\n"+
"Uef2uzXUgv8RUqX7E5cVkcZbC6SkENjCYteN3FQ3sEuOvE0waqKJKjIxL4KCXS+y\n"+
"5OT8RUmhj8r5BjJUugPoQSwfy2IB2/QeDL51sqfQMO0bib/aoAkFx0tXhLhOWYZO\n"+
"mUXwhtqnUoEUmFbKa0nJvjuBaX9KAyk/O41CtbCZflQCrDM5Z92TfzqdUUCr38we\n"+
"MylDFP42W76optrg3fDaX0FWjOJBa4kydTcHSc17UmfpBbacIExtFfeAmY0o4oib\n"+
"cUFcO8BTaJHQnWNhao6F34uHAgMBAAGjYzBhMB8GA1UdIwQYMBaAFIJC4AvxcTdV\n"+
"orcEXEHetfIJex3rMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMCYGA1UdEQQfMB2C\n"+
"G2dhbWVvbi4xNzIuMjAuMjU1LjcxLm5pcC5pbzANBgkqhkiG9w0BAQsFAAOCAgEA\n"+
"UX2qSVaqJiZkBWKDwdPQLicmfa1UrNjLlYAY7u/5LeC4EbdTQ/4x2quWmnBD3N2t\n"+
"08zNR9LG2AFmuJTYaad6GD4vqQLjG3bIA0tAp+NY8VCILDyOjKNpie4w21PNG0dF\n"+
"cpQ1RKokog6vaND92lIKUS+IVBJeRtlLYt0/A/QQN6fVw+Xh8KKho9cFK8AfNeU5\n"+
"ZlgNEvrh4FvKSGAadNVJDfFCY2WXs3DGtvYIZKIPZdgY3EAwUtrQo59IYWZwAhUw\n"+
"Zd+SEFHZrs56O3xZB6R7/5PvL2P9Lu7lvcNDMfYHx4dPtQuejUrmh8ItCDiaRYzZ\n"+
"ZdeHVvyBueonnHOfj/KQ/s0/pAug1bvyj+lbhewH3wXUppAFNdn0/6h1o+H3Ugdm\n"+
"OmU/7/7fCXCVJ5GZTUGP0OdLmh8ClUDi1KBhyORhVchWHbmiHs1Okqis4UDg9iFy\n"+
"PWWV80+NetVazvav3T5k7vr7/hia3Fp8i3iF5Lhx8vwl52vbmX5MCzFLImsFbwW5\n"+
"QbH/cGWlNqf5pJyvUld1xNldu7aqMOSsj5MAH6GaIWa5ctX9zQ2CVPP/vTFFoV8v\n"+
"5CxWM0NRriurIg3UhKLJZr2ODRoJAQrqDgy7FHO6yHwlumfrKqMW/QFiKC3UhNOU\n"+
"3Xv1UHiJnFZ7kNbRl5Zd/pc95BLSmYNGwICftpxyg0Q=\n"+
"-----END CERTIFICATE-----\n";

    String key = ""+
"-----BEGIN PRIVATE KEY-----\n"+
"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\n"+
"MARrGBdzdPxzmrgtlbOLV1IFcxzsEk7b\n"+
"-----END PRIVATE KEY-----\n";

    @Test
    public void testWorking(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        claimsBuilder.audience("server");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);


        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertTrue("jwt is supposed to be valid", jwt.isValid());
    }

    @Test
    public void testAudienceRebuild(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        claimsBuilder.audience("server");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertTrue("jwt is supposed to be valid", jwt.isValid());

        String serverJwtText = jwtv.clientToServer(jwt);

        assertNotNull("jwt conversion should not be null", serverJwtText);
        SignedJWT serverJwt = jwtv.getJWT(serverJwtText);

        assertNotNull("jwt did not parse", serverJwt);
        assertTrue("jwt is supposed to be valid", serverJwt.isValid());
        System.out.println(serverJwtText);
        assertTrue("jwt audience should now be server", serverJwt.getClaim("aud").equals("server"));
    }   

    @Test
    public void testExpired(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now().minus(Period.ofDays(2)));
        claimsBuilder.expiresAt(Instant.now().minus(Period.ofDays(1)));
        claimsBuilder.audience("server");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertFalse("jwt is supposed to be invalid", jwt.isValid());
    }

    @Test
    public void testMissingSubject(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        //claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        claimsBuilder.audience("server");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertFalse("jwt is supposed to be invalid", jwt.isValid());
    }

    @Test
    public void testMissingAudience(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        //claimsBuilder.audience("server");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertFalse("jwt is supposed to be invalid", jwt.isValid());
    }

    @Test
    public void testMissingId(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        claimsBuilder.claim("name", "stilettos");
        //claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        claimsBuilder.audience("client");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertFalse("jwt is supposed to be invalid", jwt.isValid());
    }

    @Test
    public void testMissingName(){
        SignedJWTValidator jwtv = new SignedJWTValidator();

        System.setProperty("JWT_PRIVATE_KEY", key);
        System.setProperty("JWT_PUBLIC_CERT", cert);

        //poke the postconstruct from the test
        jwtv.readKeyAndCert();

        //if we made it this far, then at least key/cert loading works ;p
        assertNotNull("key did not parse", jwtv.signingKey);
        assertNotNull("cert did not parse", jwtv.validationCert);

        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.subject("test");
        //claimsBuilder.claim("name", "stilettos");
        claimsBuilder.claim("id", "test");
        //token must not be expired to pass test!
        claimsBuilder.issuedAt(Instant.now());
        claimsBuilder.expiresAt(Instant.now().plus(Period.ofDays(1)));
        claimsBuilder.audience("client");
        String newJwt = claimsBuilder.jws().sign(jwtv.signingKey);

        SignedJWT jwt = jwtv.getJWT(newJwt);

        assertNotNull("jwt did not parse", jwt);
        assertFalse("jwt is supposed to be invalid", jwt.isValid());
    }



}
