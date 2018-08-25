package software.sandc.springframework.security.jwt.impl.consumer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.consumer.JWTAuthorityConnector;
import software.sandc.springframework.security.jwt.consumer.JWTConsumer;
import software.sandc.springframework.security.jwt.impl.DefaultJWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.impl.DefaultSigningKeyResolver;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;
import software.sandc.springframework.security.jwt.model.parameter.DisableXSRFParameter;
import software.sandc.springframework.security.jwt.model.parameter.IgnoreExpiryParameter;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;
import software.sandc.springframework.security.jwt.util.BooleanUtils;

public class DefaultJWTConsumer implements JWTConsumer, InitializingBean  {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultJWTConsumer.class);
    
    protected static final long TEN_YEARS_IN_SECONDS = 315360000;
    
    public static final String SPRING_SECURITY_JWT_XSRF_PARAMETER_NAME = "xsrf-token";
    public static final String SPRING_SECURITY_JWT_SESSION_ID_PARAMETER_NAME = "jti";   
    public static final String SPRING_SECURITY_JWT_AUTHORITIES_PARAMETER_NAME = "authorities";
    
    protected String authoritiesParameterName = SPRING_SECURITY_JWT_AUTHORITIES_PARAMETER_NAME;
    protected String sessionIdParameterName = SPRING_SECURITY_JWT_SESSION_ID_PARAMETER_NAME;
    protected String xsrfParameterName = SPRING_SECURITY_JWT_XSRF_PARAMETER_NAME;

    protected JWTAuthorityConnector jwtAuthorityConnector;
    protected SigningKeyResolver signingKeyResolver;
    protected JWTRequestResponseHandler jwtRequestResponseHandler;
    
    public DefaultJWTConsumer(){
    }
    
    public DefaultJWTConsumer(JWTAuthorityConnector jwtAuthorityConnector){
        this.jwtAuthorityConnector = jwtAuthorityConnector;
    }

    @Override
        public void afterPropertiesSet() throws Exception {
            Assert.notNull(this.jwtAuthorityConnector, "jwtAuthorityConnector must be specified");
            if (jwtRequestResponseHandler == null) {
                jwtRequestResponseHandler = new DefaultJWTRequestResponseHandler();
            }
            if (signingKeyResolver == null) {
                signingKeyResolver = new DefaultSigningKeyResolver(jwtAuthorityConnector);
            }
        }

    @Override
    public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response) {
    	LOGGER.trace("Authenticate JWT request");
        JWTContext jwtContext = null;
        TokenContainer tokenContainer = jwtRequestResponseHandler.getTokenFromRequest(request);
        if (tokenContainer != null) {
            try {
                Parameters parameters = jwtRequestResponseHandler.getParametersFromRequest(request);
                jwtContext = validate(tokenContainer, parameters);
            } catch (ExpiredTokenException e) {
                    jwtContext = jwtAuthorityConnector.requestRenew(request);
            }
            handleJWTContext(request, response, jwtContext);
        }
        return jwtContext;
    }

    @Override
    public JWTContext validate(TokenContainer tokenContainer, Parameters parameters)
            throws InvalidTokenException, ExpiredTokenException {
    	LOGGER.trace("Validate token container: {} with parameters: {}", tokenContainer, parameters);
        if (tokenContainer == null) {
            throw new InvalidTokenException("Token container is empty");
        }
        JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver);
        if (parameters != null && BooleanUtils.isTrue(parameters.getValueOf(IgnoreExpiryParameter.class))) {
            jwtParser = jwtParser.setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
        }
        String jwtToken = tokenContainer.getJwtToken();
        String jwtMode = getJWTModeFromParameters(parameters);
        try {
            Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
            Claims claims = jws.getBody();
            String xsrfToken = tokenContainer.getXsrfToken();
            validateXSRF(claims, xsrfToken);
            String principal = extractPrincipal(claims);
            String sessionId = extractSessionId(claims);
            Collection<GrantedAuthority> authorities = getAuthorities(claims);
            JWTContext jwtContext = createJWTContext(principal, sessionId, xsrfToken, authorities, jwtMode, jwtToken);
            return jwtContext;
        } catch (ExpiredJwtException e) {
        	String msg = "JWT Token is expired.";
			LOGGER.trace(msg);
            throw new ExpiredTokenException(msg);
        } catch (JwtException e) {
        	String msg = "JWT Token is invalid.";
            throw new InvalidTokenException(msg, e);
        }
    }

    public void setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        this.signingKeyResolver = signingKeyResolver;
    }

    public void setJWTAuthorityConnector(JWTAuthorityConnector jwtAuthorityConnector) {
        this.jwtAuthorityConnector = jwtAuthorityConnector;
    }
    
    public void setJwtRequestResponseHandler(JWTRequestResponseHandler jwtRequestResponseHandler) {
        this.jwtRequestResponseHandler = jwtRequestResponseHandler;
    }

    public JWTRequestResponseHandler getJwtRequestResponseHandler() {
        return this.jwtRequestResponseHandler;
    }

    public void setAuthoritiesParameterName(String authoritiesParameterName) {
        this.authoritiesParameterName = authoritiesParameterName;
    }

    public void setXsrfParameterName(String xsrfParameterName) {
        this.xsrfParameterName = xsrfParameterName;
    }

    public void setSessionIdParameterName(String sessionIdParameterName) {
        this.sessionIdParameterName = sessionIdParameterName;
    }

    protected void handleJWTContext(HttpServletRequest request, HttpServletResponse response, JWTContext jwtContext) {
        if (jwtContext != null && jwtContext.isAuthenticated()) {
            JWTAuthentication authentication = jwtContext.getAuthentication();
            SecurityContextHolder.getContext().setAuthentication(authentication);
            jwtRequestResponseHandler.putTokenToResponse(request, response, jwtContext.getTokenContainer());
        }
    }
    
    protected void validateXSRF(Claims claims, String xsrfToken) {
        String xsrfTokenFromClaim = claims.get(xsrfParameterName, String.class);
        if (xsrfTokenFromClaim != null && !xsrfTokenFromClaim.equals(xsrfToken)) {
            throw new InsufficientAuthenticationException("XSRF Token is not valid.");
        }
    }
    
    protected String extractPrincipal(Claims claims) {
        String principal = claims.getSubject();

        if (principal == null || principal.isEmpty()) {
            throw new InvalidTokenException("A valid token must provide a non-empty principal value.");
        }

        return principal;
    }

    protected String extractSessionId(Claims claims) {
        String sessionId = claims.get(sessionIdParameterName, String.class);
        return sessionId;
    }
    
    protected Collection<GrantedAuthority> getAuthorities(Claims claims) {
        String authoritiesAsString = claims.get(authoritiesParameterName, String.class);
        if (authoritiesAsString == null || authoritiesAsString.isEmpty()) {
            return null;
        } else {
            List<String> authoritiesStringList = Arrays.asList(authoritiesAsString.split(","));
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            for (String authority : authoritiesStringList) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }
            return authorities;
        }
    }

    protected JWTContext createJWTContext(String principal, String sessionId, String xsrfToken,
            Collection<? extends GrantedAuthority> authorities,  String jwtMode, String jwtToken) {
        TokenContainer tokenContainer = new TokenContainer(jwtMode, jwtToken, xsrfToken);
        JWTAuthentication authentication = new JWTAuthentication(principal, sessionId, authorities);
        JWTContext jwtContext = new JWTContext(authentication, tokenContainer);
        return jwtContext;
    }

    protected String getJWTModeFromParameters(Parameters parameters) {
        
        if(parameters != null && BooleanUtils.isTrue(parameters.getValueOf(DisableXSRFParameter.class))){
            return DefaultJWTRequestResponseHandler.SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_APP;
        }else{
            return DefaultJWTRequestResponseHandler.SPRING_SECURITY_JWT_REQUEST_HEADER_JWT_MODE_VALUE_WEB;
        }
    }

}
