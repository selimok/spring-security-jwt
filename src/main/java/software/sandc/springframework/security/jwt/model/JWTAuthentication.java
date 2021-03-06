package software.sandc.springframework.security.jwt.model;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * {@link JWTAuthentication} is a sub class {@link AbstractAuthenticationToken}.
 * This class contains authentication related data which processed by spring
 * security framework.
 * 
 * @author selimok
 */
@JsonDeserialize(using = JWTAuthenticationSerializer.class)
public class JWTAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String principal;

    private final String sessionId;

    /**
     * Constructor for serialization only, DO NOT USE!
     */
    private JWTAuthentication() {
        super(null);
        this.sessionId = null;
        this.principal = null;
    }

    /**
     * Create a {@link JWTAuthentication} instance for a specific user
     * (identified by principal parameter) and its authorities (roles and
     * rights).
     * 
     * @param principal
     *            Unique user identifier like user name, user id, email address
     *            etc.
     * @param authorities
     *            the collection of {@link GrantedAuthority}'s for the principal
     *            represented by this authentication object.
     */
    public JWTAuthentication(String principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.sessionId = null;
        this.setAuthenticated(true);
    }

    /**
     * Create a {@link JWTAuthentication} instance for a specific user
     * (identified by principal parameter), session id and its authorities
     * (roles and rights).
     * 
     * @param principal
     *            Unique user identifier like user name, user id, email address
     *            etc.
     * @param sessionId
     *            An additional session identifier to link user a specific
     *            session. The session id may be null.
     * @param authorities
     *            the collection of {@link GrantedAuthority}'s for the principal
     *            represented by this authentication object.
     */
    public JWTAuthentication(String principal, String sessionId, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.sessionId = sessionId;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    /**
     * Get principal (unique user identifier like user name, user id, email
     * address etc.)
     * 
     * @return Principal as String.
     */
    @Override
    public String getPrincipal() {
        return this.principal;
    }

    /**
     * Get session id (if exists)
     * 
     * @return Session id as String.
     */
    public String getSessionId() {
        return this.sessionId;
    }

}
