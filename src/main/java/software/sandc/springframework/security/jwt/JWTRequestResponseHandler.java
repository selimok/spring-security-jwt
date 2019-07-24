package software.sandc.springframework.security.jwt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.util.WebUtils;

import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.parameter.DisableXSRFParameter;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;

public class JWTRequestResponseHandler {

    public static final String SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER = "JWT-TOKEN";
    public static final String SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER = "XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_RESPONSE_HEADER_XSRF = "XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF = "X-XSRF-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT = "X-JWT-TOKEN";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE = "X-JWT-MODE";
    public static final String SPRING_SECURITY_JWT_RESPONSE_HEADER_JWT = "JWT-TOKEN";

    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_WEB = "web";
    public static final String SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_APP = "app";

    protected String jwtCookieParameterName = SPRING_SECURITY_JWT_COOKIE_JWT_PARAMETER;
    protected String jwtRequestHeaderParameterName = SPRING_SECURITY_JWT_REQUEST_HEADER_JWT;
    protected String jwtResponseHeaderParameterName = SPRING_SECURITY_JWT_RESPONSE_HEADER_JWT;
    protected String jwtModeRequestHeaderParameterName = SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE;
    protected String xsrfCookieParameterName = SPRING_SECURITY_JWT_COOKIE_XSRF_PARAMETER;
    protected String xsrfResponseHeaderParameterName = SPRING_SECURITY_JWT_RESPONSE_HEADER_XSRF;
    protected String xsrfRequestHeaderParameterName = SPRING_SECURITY_JWT_REQUEST_HEADER_XSRF;
    protected String cookiePath = "/";
    protected boolean secureCookie = false;

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

    public Parameters getParametersFromRequest(HttpServletRequest request) {
        if (isJWTRequestedInAppMode(request)) {
            return new Parameters(new DisableXSRFParameter(true));
        }
        return null;
    }
    
    public void putTokenToResponse(HttpServletRequest request, HttpServletResponse response,
            TokenContainer tokenContainer) {

        String jwtToken = tokenContainer.getJwtToken();
        
        if (isJWTRequestedInAppMode(request)) {
            response.setHeader(jwtResponseHeaderParameterName, jwtToken);
            
        } else {
            Cookie jwtTokenCookie = new Cookie(jwtCookieParameterName, jwtToken);
            // Setting JWT token as HttpOnly is really important. JWT Token
            // should only be readable by browser and none of java script codes.
            // Otherwise token can be breached in case of XSS attacks.
            jwtTokenCookie.setHttpOnly(true);
            jwtTokenCookie.setSecure(secureCookie);
            jwtTokenCookie.setPath(cookiePath);

            String xsrfToken = tokenContainer.getXsrfToken();
            Cookie xsrfTokenCookie = new Cookie(xsrfCookieParameterName, xsrfToken);
            xsrfTokenCookie.setSecure(secureCookie);
            xsrfTokenCookie.setPath(cookiePath);
            response.setHeader(xsrfResponseHeaderParameterName, xsrfToken);
            
            response.addCookie(jwtTokenCookie);
            response.addCookie(xsrfTokenCookie);
        }

    }

    public String getCookiePath() {
        return cookiePath;
    }

    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }

    public boolean isSecureCookie() {
        return secureCookie;
    }

    public void setSecureCookie(boolean secureCookie) {
        this.secureCookie = secureCookie;
    }
    

    public String getJwtCookieParameterName() {
        return jwtCookieParameterName;
    }

    public void setJwtCookieParameterName(String jwtCookieParameterName) {
        this.jwtCookieParameterName = jwtCookieParameterName;
    }

    public String getJwtRequestHeaderParameterName() {
        return jwtRequestHeaderParameterName;
    }

    public void setJwtRequestHeaderParameterName(String jwtRequestHeaderParameterName) {
        this.jwtRequestHeaderParameterName = jwtRequestHeaderParameterName;
    }

    public String getJwtResponseHeaderParameterName() {
        return jwtResponseHeaderParameterName;
    }

    public void setJwtResponseHeaderParameterName(String jwtResponseHeaderParameterName) {
        this.jwtResponseHeaderParameterName = jwtResponseHeaderParameterName;
    }

    public String getJwtModeRequestHeaderParameterName() {
        return jwtModeRequestHeaderParameterName;
    }

    public void setJwtModeRequestHeaderParameterName(String jwtModeRequestHeaderParameterName) {
        this.jwtModeRequestHeaderParameterName = jwtModeRequestHeaderParameterName;
    }

    public String getXsrfCookieParameterName() {
        return xsrfCookieParameterName;
    }

    public void setXsrfCookieParameterName(String xsrfCookieParameterName) {
        this.xsrfCookieParameterName = xsrfCookieParameterName;
    }

    public String getXsrfResponseHeaderParameterName() {
        return xsrfResponseHeaderParameterName;
    }

    public void setXsrfResponseHeaderParameterName(String xsrfResponseHeaderParameterName) {
        this.xsrfResponseHeaderParameterName = xsrfResponseHeaderParameterName;
    }

    public String getXsrfRequestHeaderParameterName() {
        return xsrfRequestHeaderParameterName;
    }

    public void setXsrfRequestHeaderParameterName(String xsrfRequestHeaderParameterName) {
        this.xsrfRequestHeaderParameterName = xsrfRequestHeaderParameterName;
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
        Cookie cookie = WebUtils.getCookie(request, jwtCookieParameterName);
        if (cookie != null && cookie.getValue() != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    protected String getJWTTokenFromHeader(HttpServletRequest request) {
        return request.getHeader(jwtRequestHeaderParameterName);
    }

    protected String getXSRFTokenFromHeader(HttpServletRequest request) {
        return request.getHeader(xsrfRequestHeaderParameterName);
    }

    protected String getJWTModeFromHeader(HttpServletRequest request) {
        String jwtMode = request.getHeader(jwtModeRequestHeaderParameterName);
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
