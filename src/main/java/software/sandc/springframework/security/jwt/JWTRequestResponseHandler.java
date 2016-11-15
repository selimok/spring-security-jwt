package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface JWTRequestResponseHandler {
	
	JWTAuthenticationToken getTokenFromRequest(HttpServletRequest request);
	
	void putTokenToResponse(HttpServletResponse response, JWTAuthenticationToken token);

}
