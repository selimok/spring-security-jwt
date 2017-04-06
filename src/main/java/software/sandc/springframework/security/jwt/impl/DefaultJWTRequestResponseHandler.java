package software.sandc.springframework.security.jwt.impl;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.util.WebUtils;

import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.parameter.DisableXSRFParameter;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;

public class DefaultJWTRequestResponseHandler implements JWTRequestResponseHandler {

    public static final String SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER = "JWT-TOKEN";
    public static final String SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER = "XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_RESPONSE_HEADER_XSRF = "XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF = "X-XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT = "X-JWT-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE = "X-JWT-MODE";
    public static final String SPRING_SECURITY_JWT_RESPONSE_HEADER_JWT = "JWT-TOKEN";

    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_WEB = "web";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_APP = "app";

    protected String jwtCookieParameter = SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER;
    protected String jwtRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_JWT;
    protected String jwtResponseHeaderParameter = SPRING_SECURITY_JWT_RESPONSE_HEADER_JWT;
    protected String jwtModeRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE;
    protected String xsrfCookieParameter = SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER;
    protected String xsrfResponseHeaderParameter = SPRING_SECURITY_JWT_RESPONSE_HEADER_XSRF;
    protected String xsrfRequestHeaderParameter = SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF;
    protected String cookiePath = "/";
    protected boolean secureCookie = false;

    @Override
    public TokenContainer getTokenFromRequest(HttpServletRequest request) {
        String jwtToken = getJWTTokenFromRequest(request);
        if (jwtToken == null || jwtToken.isEmpty()) {
            return null;
        } else {
            String xsrfToken = getXSRFTokenFromHeader(request);
            String jwtMode = getJWTModeFromHeader(request);
            return new TokenContainer(jwtMode, jwtToken, xsrfToken);
        }
    }

    @Override
    public Parameters getParametersFromRequest(HttpServletRequest request) {
        if (isJWTRequestedInAppMode(request)) {
            return new Parameters(new DisableXSRFParameter(true));
        }
        return null;
    }
    
    @Override
    public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
            TokenContainer tokenContainer) {

        String jwtToken = tokenContainer.getJwtToken();
        
        if (isJWTRequestedInAppMode(request)) {
            response.setHeader(jwtResponseHeaderParameter, jwtToken);
            
        } else {
            Cookie jwtTokenCookie = new Cookie(jwtCookieParameter, jwtToken);
            // Setting JWT token as HttpOnly is really important. JWT Token
            // should only be readable by browser and none of java script codes.
            // Otherwise token can be breached in case of XSS attacks.
            jwtTokenCookie.setHttpOnly(true);
            jwtTokenCookie.setSecure(secureCookie);
            jwtTokenCookie.setPath(cookiePath);

            String xsrfToken = tokenContainer.getXsrfToken();
            Cookie xsrfTokenCookie = new Cookie(xsrfCookieParameter, xsrfToken);
            xsrfTokenCookie.setSecure(secureCookie);
            xsrfTokenCookie.setPath(cookiePath);
            response.setHeader(xsrfResponseHeaderParameter, xsrfToken);
            
            response.addCookie(jwtTokenCookie);
            response.addCookie(xsrfTokenCookie);
        }

    }

    public void setJwtCookieParameter(String jwtCookieParameter) {
        this.jwtCookieParameter = jwtCookieParameter;
    }

    public void setJwtRequestHeaderParameter(String jwtRequestHeaderParameter) {
        this.jwtRequestHeaderParameter = jwtRequestHeaderParameter;
    }

    public void setJwtModeRequestHeaderParameter(String jwtModeRequestHeaderParameter) {
        this.jwtModeRequestHeaderParameter = jwtModeRequestHeaderParameter;
    }

    public void setJwtResponseHeaderParameter(String jwtResponseHeaderParameter) {
        this.jwtResponseHeaderParameter = jwtResponseHeaderParameter;
    }
    
    public void setXsrfResponseHeaderParameter(String xsrfResponseHeaderParameter) {
        this.xsrfResponseHeaderParameter = xsrfResponseHeaderParameter;
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
        if (isJWTRequestedInAppMode(request)) {
            jwtToken = getJWTTokenFromHeader(request);
        } else {
            jwtToken = getJWTTokenFromCookie(request);
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

    protected String getJWTModeFromHeader(HttpServletRequest request) {
        String jwtMode = request.getHeader(jwtModeRequestHeaderParameter);
        if(SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_APP.equals(jwtMode)){
            return jwtMode;
        }else{            
            return SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_WEB;
        }
    }

    protected boolean isJWTRequestedInAppMode(HttpServletRequest request) {
        String jwtMode = getJWTModeFromHeader(request);
        return istJWTInAppMode(jwtMode);
    }

    protected boolean istJWTInAppMode(String jwtMode) {
        return SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_APP.equals(jwtMode);
    }

}
