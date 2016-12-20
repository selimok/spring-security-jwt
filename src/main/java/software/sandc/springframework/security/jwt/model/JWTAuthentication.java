package software.sandc.springframework.security.jwt.model;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * {@link JWTAuthentication} is a sub class {@link AbstractAuthenticationToken}.
 * This class contains authentication related data which processed by spring
 * security framework.
 * 
 * @author selimok
 */
public class JWTAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String principal;

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

}
