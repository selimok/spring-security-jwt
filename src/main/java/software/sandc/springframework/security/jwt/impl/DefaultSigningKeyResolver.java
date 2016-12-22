package software.sandc.springframework.security.jwt.impl;

import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import software.sandc.springframework.security.jwt.KeyProvider;
import software.sandc.springframework.security.jwt.model.KeyType;

@SuppressWarnings("rawtypes")
public class DefaultSigningKeyResolver extends SigningKeyResolverAdapter implements InitializingBean {

    private KeyProvider keyProvider;

    public DefaultSigningKeyResolver(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
        return getBinarySigningKey(header);
    }

    @Override
    public byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
        return getBinarySigningKey(header);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.keyProvider, "keyProvider must be specified");
    }

    private byte[] getBinarySigningKey(JwsHeader header) {
        String keyId = header.getKeyId();

        if (keyId == null || keyId.isEmpty()) {
            throw new JwtException("JWT header does not contain key id. ");
        }

        String key;
        KeyType keyType = keyProvider.getKeyType(keyId);
        if (KeyType.ASYMMETRIC.equals(keyType)) {
            key = keyProvider.getPublicKey(keyId);
        } else if (KeyType.SYMMETRIC.equals(keyType)) {
            key = keyProvider.getPrivateKey(keyId);
        } else {
            throw new JwtException("Unknown or empty key type detected.");
        }

        if (key == null) {
            throw new JwtException("No key can be found for given key JWT header.");
        }
        return DatatypeConverter.parseBase64Binary(key);

    }

}
