package software.sandc.springframework.security.jwt.authority;

import io.jsonwebtoken.SignatureAlgorithm;
import software.sandc.springframework.security.jwt.consumer.KeyProvider;

/**
 * {@link AuthorityKeyProvider} is an extension of {@link KeyProvider} which is responsible to provide keys used for signing and
 * validating of JWT tokens. This class has additional functionalities to support JWT authority.
 * 
 * @author selimok
 *
 */
public interface AuthorityKeyProvider extends KeyProvider{

    /**
     * Get current key id for signing JWT token. Key id is used for resolving
     * key type and signing keys while creating or validating a JWT token.
     * 
     * @return non-null, non-empty key id.
     */
    String getCurrentSigningKeyId();

    /**
     * Get the signature algorithm of the related key.
     * 
     * @param keyId
     *            Unique id of the related key.
     * @return A {@link SignatureAlgorithm} value.
     */
    SignatureAlgorithm getSignatureAlgorithm(String keyId);
}
