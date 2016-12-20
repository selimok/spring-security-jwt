package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
     * Extracts tokens from HTTP request.
     * 
     * @param request
     *            HTTP request.
     * 
     * @return A {@link TokenContainer} object which contains all relevant
     *         tokens.
     */
    public TokenContainer getTokenFromRequest(HttpServletRequest request);

    /**
     * Attaches tokens to HTTP response.
     * 
     * @param request
     *            HTTP request.
     * @param response
     *            HTTP response.
     * @param tokenContainer A {@link TokenContainer} object which contains all relevant
     *         tokens.
     * 
     */
    public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
	    TokenContainer tokenContainer);

}
