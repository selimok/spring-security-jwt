package software.sandc.springframework.security.jwt.impl;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;
import software.sandc.springframework.security.jwt.KeyProvider;
import software.sandc.springframework.security.jwt.model.KeyType;
import software.sandc.springframework.security.jwt.util.RSAUtils;

@SuppressWarnings("rawtypes")
public class DefaultSigningKeyResolver extends SigningKeyResolverAdapter implements InitializingBean {

    private KeyProvider keyProvider;

    public DefaultSigningKeyResolver(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }
    
    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
    	SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(header.getAlgorithm());
    	if(signatureAlgorithm.isRsa()){
    		String signingKey = getSigningKey(header);
    		return RSAUtils.toPublicKey(signingKey);
    	}else if(signatureAlgorithm.isHmac()){
    		 byte[] keyBytes = resolveSigningKeyBytes(header, claims);
    	     return new SecretKeySpec(keyBytes, signatureAlgorithm.getJcaName());
    	}else{
    		throw new UnsupportedJwtException("Not supported signature algorithm " + signatureAlgorithm.getValue());
    	}
        
    }
    
    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(header.getAlgorithm());
        if(signatureAlgorithm.isRsa()){
            String signingKey = getSigningKey(header);
            return RSAUtils.toPublicKey(signingKey);
        }else if(signatureAlgorithm.isHmac()){
            byte[] keyBytes = resolveSigningKeyBytes(header, plaintext);
            return new SecretKeySpec(keyBytes, signatureAlgorithm.getJcaName());
        }else{
            throw new UnsupportedJwtException("Not supported signature algorithm " + signatureAlgorithm.getValue());
        }
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
        String key = getSigningKey(header);
        return TextCodec.BASE64.decode(key);

    }

	private String getSigningKey(JwsHeader header) {
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
		return key;
	}

}
