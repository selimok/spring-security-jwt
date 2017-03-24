package software.sandc.springframework.security.jwt.impl.authority;

import java.util.UUID;

import io.jsonwebtoken.SignatureAlgorithm;
import software.sandc.springframework.security.jwt.authority.AuthorityKeyProvider;
import software.sandc.springframework.security.jwt.model.KeyType;

public class FakeKeyProvider implements AuthorityKeyProvider {

    private final String privateKey;

    public FakeKeyProvider() {
        privateKey = UUID.randomUUID().toString();
    }

    @Override
    public String getCurrentSigningKeyId() {
        return "1";
    }

    @Override
    public String getPrivateKey(String keyId) {
        return privateKey;
    }

    @Override
    public String getPublicKey(String keyId) {
        return null;
    }

    @Override
    public KeyType getKeyType(String keyId) {
        return KeyType.SYMMETRIC;
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm(String keyId) {
        return SignatureAlgorithm.HS512;
    }

}
