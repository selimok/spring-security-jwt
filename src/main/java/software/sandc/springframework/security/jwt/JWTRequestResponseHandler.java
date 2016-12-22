package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.model.Parameters;
import software.sandc.springframework.security.jwt.model.TokenContainer;

/**
 * A {@link JWTRequestResponseHandler} implementation is responsible to extract
 * JWT and XSRF tokens from HTTP request and attache them in HTTP response
 * accordingly. <br>
 * <br>
 * Different implementations may have different strategies to set and get these
 * tokens from request and response. For example one implementation may attach
 * JWT token into response header, while another one may set it as cookie.
 * 
 * @author selimok
 *
 */
public interface JWTRequestResponseHandler {

    /**
     * Extract tokens from HTTP request.
     * 
     * @param request
     *            HTTP request.
     * 
     * @return A {@link TokenContainer} object which contains all relevant
     *         tokens.
     */
    public TokenContainer getTokenFromRequest(HttpServletRequest request);

    /**
     * Extract {@link Parameter} from HTTP request. The content of the returned
     * {@link Parameters} object may vary depending on the underlying
     * implementation.
     * 
     * @param request
     *            HTTP request.
     * @return {@link Parameter} object extracted from HTTP request. This value
     *         may be <b>null</b>.
     */
    public Parameters getParametersFromRequest(HttpServletRequest request);

    /**
     * Attach tokens to HTTP response.
     * 
     * @param request
     *            HTTP request.
     * @param response
     *            HTTP response.
     * @param tokenContainer
     *            A {@link TokenContainer} object which contains all relevant
     *            tokens.
     * 
     */
    public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
	    TokenContainer tokenContainer);

}
