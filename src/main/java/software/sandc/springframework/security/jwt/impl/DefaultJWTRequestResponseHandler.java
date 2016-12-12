package software.sandc.springframework.security.jwt.impl;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.util.WebUtils;

import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.model.TokenContainer;

public class DefaultJWTRequestResponseHandler implements JWTRequestResponseHandler {

	public static final String SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER = "JWT-TOKEN";
	public static final String SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER = "XSRF-TOKEN";
	public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF = "X-XSRF-TOKEN";
	public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT = "X-JWT-TOKEN";

	private String jwtCookieParameter = SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER;
	private String jwtRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_JWT;
	private String xsrfCookieParameter = SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER;
	private String xsrfRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF;
	private String cookiePath = "/";
	private boolean secureCookie = false;

	@Override
	public TokenContainer getTokenFromRequest(HttpServletRequest request) {
		String jwtToken = getJWTTokenFromRequest(request);
		if (jwtToken == null || jwtToken.isEmpty()) {
			return null;
		} else {
			String xsrfToken = getXSRFTokenFromHeader(request);
			return new TokenContainer(jwtToken, xsrfToken);
		}
	}

	@Override
	public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
			TokenContainer tokenContainer) {

		// TODO: try to read request header like X-JWT-MODE to build response
		// structure according to desired jwt-mode (e.g instead of setting jwt
		// token into cookie, set it into header)

		Cookie jwtTokenCookie = new Cookie(jwtCookieParameter, tokenContainer.getJwtToken());
		// Setting JWT token as HttpOnly is really important. JWT Token should
		// only be readable by browser and none of java script codes. Otherwise
		// token can be breached in case of XSS attacks.
		jwtTokenCookie.setHttpOnly(true);
		jwtTokenCookie.setSecure(secureCookie);
		jwtTokenCookie.setPath(cookiePath);

		Cookie xsrfTokenCookie = new Cookie(xsrfCookieParameter, tokenContainer.getXsrfToken());
		xsrfTokenCookie.setSecure(secureCookie);
		xsrfTokenCookie.setPath(cookiePath);

		response.addCookie(jwtTokenCookie);
		response.addCookie(xsrfTokenCookie);
	}

	public void setJwtCookieParameter(String jwtCookieParameter) {
		this.jwtCookieParameter = jwtCookieParameter;
	}

	public void setJwtRequestHeaderParameter(String jwtRequestHeaderParameter) {
		this.jwtRequestHeaderParameter = jwtRequestHeaderParameter;
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

	protected String getJWTTokenFromRequest(HttpServletRequest request) {
		String jwtToken = null;
		jwtToken = getJWTTokenFromCookie(request);

		if (jwtToken == null) {
			jwtToken = getJWTTokenFromHeader(request);
		}
		return jwtToken;

	}

	protected String getJWTTokenFromCookie(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookieParameter);
		if (cookie != null && cookie.getValue() != null) {
			return cookie.getValue();
		} else {
			return null;
		}
	}

	protected String getJWTTokenFromHeader(HttpServletRequest request) {
		return request.getHeader(jwtRequestHeaderParameter);
	}

	protected String getXSRFTokenFromHeader(HttpServletRequest request) {
		return request.getHeader(xsrfRequestHeaderParameter);
	}
}
