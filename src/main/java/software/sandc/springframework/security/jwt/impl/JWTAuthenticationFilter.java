package software.sandc.springframework.security.jwt.impl;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import software.sandc.springframework.security.jwt.JWTService;
import software.sandc.springframework.security.jwt.model.JWTContext;

public class JWTAuthenticationFilter extends OncePerRequestFilter {

	protected final JWTService jwtService;

	public JWTAuthenticationFilter(JWTService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		Assert.notNull(this.jwtService, "jwtService must be specified");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			attemptAuthentication(request, response);
		} catch (AuthenticationException authenticationException) {
			handleAuthenticationException(request, response, filterChain);
		}

		filterChain.doFilter(request, response);
	}

	protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		Authentication authentication = null;
		JWTContext jwtContext = jwtService.authenticateRequest(request, response);
		if(jwtContext != null){
			authentication = jwtContext.getAuthentication(); 
		}
		return authentication;
	}

	protected void handleAuthenticationException(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {
		// Do nothing
	}

}
