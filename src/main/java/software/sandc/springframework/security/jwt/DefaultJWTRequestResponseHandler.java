package software.sandc.springframework.security.jwt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.util.WebUtils;

public class DefaultJWTRequestResponseHandler implements JWTRequestResponseHandler {

	public static final String SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER = "JWT-TOKEN";
	public static final String SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER = "XSRF-TOKEN";
	public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF = "X-XSRF-TOKEN";

	private String jwtCookieParameter = SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER;
	private String xsrfCookieParameter = SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER;
	private String xsrfRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF;
	private String cookiePath = "/";
	private boolean secureCookie = true;

	@Override
	public JWTAuthenticationToken getTokenFromRequest(HttpServletRequest request) {
		String jwtToken = getJWTTokenFromRequest(request);
		if (jwtToken == null || jwtToken.isEmpty()) {
			return null;
		} else {
			String xsrfToken = getXSRFTokenFromRequest(request);
			return new JWTAuthenticationToken(jwtToken, xsrfToken);
		}
	}

	@Override
	public void putTokenToResponse(HttpServletResponse response, JWTAuthenticationToken token) {
		Cookie jwtTokenCookie = new Cookie(jwtCookieParameter, token.getJwtToken());
		// Setting JWT token as HttpOnly is really important. JWT Token should
		// only be readable by browser and none of java script codes. Otherwise
		// token can be breached in case of XSS attacks.
		jwtTokenCookie.setHttpOnly(true);
		jwtTokenCookie.setSecure(secureCookie);
		jwtTokenCookie.setPath(cookiePath);

		Cookie xsrfTokenCookie = new Cookie(xsrfCookieParameter, token.getXsrfToken());
		xsrfTokenCookie.setSecure(secureCookie);
		xsrfTokenCookie.setPath(cookiePath);

		response.addCookie(jwtTokenCookie);
		response.addCookie(xsrfTokenCookie);
	}

	public void setJwtCookieParameter(String jwtCookieParameter) {
		this.jwtCookieParameter = jwtCookieParameter;
	}

	public void setXsrfCookieParameter(String xsrfCookieParameter) {
		this.xsrfCookieParameter = xsrfCookieParameter;
	}

	public void setXsrfRequestHeaderParameter(String xsrfRequestHeaderParameter) {
		this.xsrfRequestHeaderParameter = xsrfRequestHeaderParameter;
	}

	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}

	public void setSecureCookie(boolean secureCookie) {
		this.secureCookie = secureCookie;
	}

	private String getJWTTokenFromRequest(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookieParameter);
		String jwtToken = null;
		if (cookie != null && cookie.getValue() != null) {
			jwtToken = cookie.getValue();
		}
		return jwtToken;

	}

	private String getXSRFTokenFromRequest(HttpServletRequest request) {
		return request.getHeader(xsrfRequestHeaderParameter);
	}
}
