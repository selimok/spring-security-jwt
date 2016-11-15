package software.sandc.springframework.security.jwt;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class JWTAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String principal;
	private final String jwtToken;
	private final String xsrfToken;

	public JWTAuthenticationToken(String jwtToken, String xsrfToken) {
		super(null);
		this.principal = null;
		this.jwtToken = jwtToken;
		this.xsrfToken = xsrfToken;
	}

	public JWTAuthenticationToken(String principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.jwtToken = null;
		this.xsrfToken = null;
		this.setAuthenticated(true);
	}
	
	public JWTAuthenticationToken(String jwtToken, String xsrfToken, String username,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = username;
		this.jwtToken = jwtToken;
		this.xsrfToken = xsrfToken;
		this.setAuthenticated(true);
	}

	public Object getCredentials() {
		return null;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public String getJwtToken() {
		return jwtToken;
	}

	public String getXsrfToken() {
		return xsrfToken;
	}

}
