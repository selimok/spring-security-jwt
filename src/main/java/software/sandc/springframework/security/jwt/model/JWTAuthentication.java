package software.sandc.springframework.security.jwt.model;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class JWTAuthentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String principal;

	public JWTAuthentication(String principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.setAuthenticated(true);
	}
	
	public Object getCredentials() {
		return null;
	}

	public Object getPrincipal() {
		return this.principal;
	}

}
