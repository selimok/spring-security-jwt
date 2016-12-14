package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;

public interface JWTService {

	public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response);

	public JWTContext authenticateLoginRequest(Credentials credentials, HttpServletRequest request, HttpServletResponse response);
	
	public JWTContext createAndAttach(String principal, HttpServletRequest request, HttpServletResponse response);

	/**
	 * Creates {@link JWTContext} for given principal. A {@link JWTContext}
	 * contains all relevant tokens (like JWT or XSRF Tokens) and
	 * {@link JWTAuthentication} object, which is relevant for Spring-Security.
	 * 
	 * @param principal
	 *            Unique user identifier. This can be the user name or user id
	 *            according to underlying implementation.
	 * @return Fully fledged {@link JWTContext} object.
	 */
	public JWTContext create(String principal);

	public JWTContext renew(TokenContainer tokenContainer);

	public JWTContext validate(TokenContainer tokenContainer, boolean ignoreExpiry) throws InvalidTokenException, ExpiredTokenException;


}
