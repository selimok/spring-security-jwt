package software.sandc.springframework.security.jwt.consumer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;

/**
 * {@link JWTConsumer} is the core component of spring security JWT extension. It is responsible for validate
 * tokens and handle authentication requests.
 * 
 * @author selimok
 *
 */
public interface JWTConsumer {

    /**
     * Authenticate HTTP request if the request contains JWT and related tokens are valid.<br>
     * <br>
     * The created {@link JWTAuthentication} object (which is also the part of {@link JWTContext}) is implicitly
     * attached into SecurityContextHolder to inform spring security about the authenticated user.
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
     * Validate tokens given in a {@link TokenContainer} instance. Validation procedure checks both JWT integrity and
     * also XSRF (a.k.a CSRF) token validity.
     * 
     * @param tokenContainer
     *            {@link TokenContainer} instance which contains JWT and XSRF tokens.
     * @param parameters
     *            Additional parameters to customize processing of the request. Possible parameters and their effects
     *            may differ depending on specific implementation. The parameters may be empty or null.
     * 
     * @return A fully fledged {@link JWTContext} object.
     * @throws InvalidTokenException
     *             if the token is not valid or its integrity is not ensured.
     * @throws ExpiredTokenException
     *             if the token is expired.
     */
    public JWTContext validate(TokenContainer tokenContainer, Parameters parameters)
            throws InvalidTokenException, ExpiredTokenException;

}
