package software.sandc.springframework.security.jwt.util;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.impl.TextCodec;

public class RSAUtils {

        private static final String RSA_ALGORITHM = "RSA";

        public static PublicKey toPublicKey(String x509encodedPublicKey){
            try {
                byte[] binarySigningKey = TextCodec.BASE64.decode(x509encodedPublicKey);
                KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
                PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(binarySigningKey));
                return publicKey;
            } catch (NoSuchAlgorithmException e) {
                throw new JwtException("Unexpected algorithm exception.", e);
            } catch (InvalidKeySpecException e) {
                throw new JwtException("Unexpected key spec exception.", e);
            }
        }
        
        public static PrivateKey toPrivateKey(String pkcs8encodedPublicKey){
            try {
                byte[] binarySigningKey = TextCodec.BASE64.decode(pkcs8encodedPublicKey);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(binarySigningKey));
                return privateKey;
            } catch (NoSuchAlgorithmException e) {
                throw new JwtException("Unexpected algorithm exception.", e);
            } catch (InvalidKeySpecException e) {
                throw new JwtException("Unexpected key spec exception.", e);
            }
        }
        
        public static String keyToString(Key key){
            return TextCodec.BASE64.encode(key.getEncoded());
        }
        
        
        
        
}
