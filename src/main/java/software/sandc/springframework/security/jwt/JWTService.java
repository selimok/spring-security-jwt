package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;

/**
 * {@link JWTService} is the core component of spring security JWT extension. It
 * is responsible for create, validate, renew tokens and handle authentication
 * requests.
 * 
 * @author selimok
 *
 */
public interface JWTService {

    /**
     * Authenticate HTTP request if the request contains JWT and related tokens
     * and tokens are valid.<br>
     * <br>
     * The created {@link JWTAuthentication} object (which is also the part of
     * {@link JWTContext}) is implicitly attached into SecurityContextHolder to
     * inform spring security about the authenticated user.
     * 
     * 
     * @param request
     *            HTTP request
     * @param response
     *            HTTP response
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response);

    /**
     * Authenticate login request if the provided credentials are valid.<br>
     * <br>
     * The created {@link JWTAuthentication} object (which is also the part of
     * {@link JWTContext}) is implicitly attached into SecurityContextHolder to
     * inform spring security about the authenticated user.
     * 
     * @param credentials
     *            {@link Credentials} instance which contains principal (unique
     *            user identifier like user name, user id, email address etc.)
     *            and password.
     * @param request
     *            HTTP request
     * @param response
     *            HTTP response
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext authenticateLoginRequest(Credentials credentials, HttpServletRequest request,
	    HttpServletResponse response);

    /**
     * Create a fully fledged {@link JWTContext} for given principal and attach
     * it into given HTTP Response. <br>
     * <br>
     * The created {@link JWTAuthentication} object (which is also the part of
     * {@link JWTContext}) is implicitly attached into SecurityContextHolder to
     * inform spring security about the authenticated user.
     * 
     * @param principal
     *            Unique user identifier. This can be the user name or user id
     *            according to underlying implementation.
     * @param request
     *            HTTP request (may be used to read clients preferences for
     *            token handling)
     * @param response
     *            HTTP response
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext createAndAttach(String principal, HttpServletRequest request, HttpServletResponse response);

    /**
     * Create a fully fledged {@link JWTContext} for given principal.
     * 
     * @param principal
     *            Unique user identifier. This can be the user name or user id
     *            according to underlying implementation.
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext create(String principal);

    /**
     * Renew tokens given in the {@link TokenContainer} object.
     * 
     * @param tokenContainer
     *            {@link TokenContainer} instance which contains JWT and XSRF
     *            tokens.
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext renew(TokenContainer tokenContainer);

    /**
     * Validate tokens given in a {@link TokenContainer} instance. Validation
     * procedure checks both JWT integrity and also XSRF (a.k.a CSRF) token
     * validity.
     * 
     * @param tokenContainer
     *            {@link TokenContainer} instance which contains JWT and XSRF
     *            tokens.
     * @param ignoreExpiry
     *            If this flag is true the validation ignores token expiration
     *            dates and an expired token may be considered as valid, if all
     *            other integrity checks are passed.
     * @return A fully fledged {@link JWTContext} object.
     * @throws InvalidTokenException
     *             if the token is not valid or its integrity is not ensured.
     * @throws ExpiredTokenException
     *             if the token is expired.
     */
    public JWTContext validate(TokenContainer tokenContainer, boolean ignoreExpiry)
	    throws InvalidTokenException, ExpiredTokenException;

}
