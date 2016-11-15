package software.sandc.springframework.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class JWTAuthenticationFilter extends OncePerRequestFilter {

	private JWTRequestResponseHandler jwtRequestResponseHandler = new DefaultJWTRequestResponseHandler();

	private AuthenticationManager authenticationManager;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager){
		this.authenticationManager = authenticationManager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// Check if request is pre-authenticated
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (isPreAuthenticated(authentication)) {
			authentication = new JWTAuthenticationToken(authentication.getPrincipal().toString(),
					authentication.getAuthorities());
		} else {
			// If request is not pre-authenticated (by using username, password
			// method) try to extract JWT and XSRF tokens from request
			authentication = jwtRequestResponseHandler.getTokenFromRequest(request);

		}
		
		if (authentication != null) {
			try {
				authentication = authenticationManager.authenticate(authentication);
				if (authentication != null && authentication.isAuthenticated()) {
					JWTAuthenticationToken jwtAuthenticationToken = (JWTAuthenticationToken) authentication;
					SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);
					jwtRequestResponseHandler.putTokenToResponse(response, jwtAuthenticationToken);
				}
			} catch (AuthenticationException authenticationException) {
				handleAuthenticationException(authentication, request, response, filterChain);
			}
		}
		
		filterChain.doFilter(request, response);
	}

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		Assert.notNull(this.authenticationManager, "authenticationManager must be specified");
	}

	/**
	 * TODO: Fix javadoc The authentication manager for validating the ticket.
	 *
	 * @param authenticationManager
	 *            the authentication manager
	 */
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public void setJwtRequestResponseHandler(JWTRequestResponseHandler jwtRequestResponseHandler) {
		this.jwtRequestResponseHandler = jwtRequestResponseHandler;
	}

	protected void handleAuthenticationException(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain) {

	}

	private boolean isPreAuthenticated(Authentication authentication) {
		return authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() != null;
	}

}
