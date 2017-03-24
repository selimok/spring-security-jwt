package software.sandc.springframework.security.jwt.authority;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.consumer.JWTConsumer;
import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;

/**
 * {@link JWTAuthority} is the core component of spring security JWT extension. It
 * is responsible for create, validate, renew tokens and handle authentication
 * requests.
 * 
 * @author selimok
 *
 */
public interface JWTAuthority extends JWTConsumer {

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
     * @param parameters
     *            Additional parameters to customize processing of the request.
     *            Possible parameters and their effects may differ depending on
     *            specific implementation. The parameters may be empty or null.
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext createAndAttach(String principal, HttpServletRequest request, HttpServletResponse response,
            Parameters parameters);

    /**
     * Create a fully fledged {@link JWTContext} for given principal.
     * 
     * @param principal
     *            Unique user identifier. This can be the user name or user id
     *            according to underlying implementation.
     * @param parameters
     *            Additional parameters to customize processing of the request.
     *            Possible parameters and their effects may differ depending on
     *            specific implementation. The parameters may be empty or null.
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext create(String principal, Parameters parameters);

    /**
     * Renew tokens given in the {@link TokenContainer} object.
     * 
     * @param tokenContainer
     *            {@link TokenContainer} instance which contains JWT and XSRF
     *            tokens.
     * @param parameters
     *            Additional parameters to customize processing of the request.
     *            Possible parameters and their effects may differ depending on
     *            specific implementation. The parameters may be empty or null.
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext renew(TokenContainer tokenContainer, Parameters parameters);

    /**
     * Authenticate HTTP request if the request contains JWT and renew it if renewable. <br>
     * <br>
     * The created {@link JWTAuthentication} object (which is also the part of {@link JWTContext}) is implicitly
     * attached into SecurityContextHolder to inform spring security about the authenticated user.<br>
     * <br>
     * Renewed token will be attached automatically into the response object.
     * 
     * @param request
     *            HTTP request (may be used to read clients preferences for token handling)
     * @param response
     *            HTTP response
     * @return A fully fledged {@link JWTContext} object.
     */
    public JWTContext renew(HttpServletRequest request, HttpServletResponse response);
   

}
