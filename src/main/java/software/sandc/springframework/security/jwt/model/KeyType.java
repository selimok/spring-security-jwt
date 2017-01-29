package software.sandc.springframework.security.jwt.model;

/**
 * {@link KeyType} indicates the type of a certain key. A key type may be a
 * symmetric or asymmetric key (private-public).
 * 
 * @author selimok
 */
public enum KeyType {
    /**
     * Symmetric key (private key only)
     */
    SYMMETRIC,
    
    /**
     * Asymmetric key (private -public key pair)
     */
    ASYMMETRIC;
}
