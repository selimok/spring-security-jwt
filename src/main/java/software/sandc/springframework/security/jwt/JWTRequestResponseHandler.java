package software.sandc.springframework.security.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import software.sandc.springframework.security.jwt.model.TokenContainer;

public interface JWTRequestResponseHandler {

	public TokenContainer getTokenFromRequest(HttpServletRequest request);

	public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
			TokenContainer tokenContainer);

}
