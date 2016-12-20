package software.sandc.springframework.security.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import software.sandc.springframework.security.jwt.model.KeyType;

/**
 * {@link KeyProvider} is responsible to provide keys used for
 * signing and validating of JWT tokens.
 * 
 * @author selimok
 *
 */
public interface KeyProvider {

    /**
     * Get current key id for signing JWT token. Key id is used for resolving
     * key type and signing keys while creating or validating a JWT token.
     * 
     * @return non-null, non-empty key id.
     */
    String getCurrentSigningKeyId();

    /**
     * Get private key for given key id. If the key type is symmetric, this
     * method returns the symmetric signing key.
     * 
     * @param keyId
     *            Unique id of the desired key.
     * @return Private or symmetric key depending on key type.
     */
    String getPrivateKey(String keyId);

    /**
     * Get public key for given key id. If the key type is symmetric, this
     * method returns a null value.
     * 
     * @param keyId
     *            Unique id of the desired key.
     * @return Public key or null depending on key type.
     */
    String getPublicKey(String keyId);

    /**
     * Get the type of the related key. The possible values are SYMMETRIC or
     * ASYMMETRIC as enumeration type.
     * 
     * @param keyId
     *            Unique id of the related key.
     * @return Key type.
     */
    KeyType getKeyType(String keyId);

    /**
     * Get the signature algorithm of the related key.
     * 
     * @param keyId
     *            Unique id of the related key.
     * @return A {@link SignatureAlgorithm} value.
     */
    SignatureAlgorithm getSignatureAlgorithm(String keyId);
}
