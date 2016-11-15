package software.sandc.springframework.security.jwt;

public interface SigningKeyProvider {

	String getCurrentSigningKeyId();

	String getSigningKey(String keyId);

}
