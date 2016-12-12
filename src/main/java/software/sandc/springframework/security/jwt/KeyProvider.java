package software.sandc.springframework.security.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import software.sandc.springframework.security.jwt.model.KeyType;

public interface KeyProvider {

	/**
	 * Get current key id for signing JWT token. Key id is used for resolving
	 * key type and signing keys while creating or validating a JWT token.
	 * 
	 * @return non-null, non-empty key id.
	 */
	String getCurrentSigningKeyId();

	String getPrivateKey(String keyId);

	String getPublicKey(String keyId);

	KeyType getKeyType(String keyId);

	SignatureAlgorithm getSignatureAlgorithm(String keyId);
}
