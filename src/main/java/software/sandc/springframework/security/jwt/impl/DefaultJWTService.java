package software.sandc.springframework.security.jwt.impl;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;
import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.JWTService;
import software.sandc.springframework.security.jwt.KeyProvider;
import software.sandc.springframework.security.jwt.SessionProvider;
import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.Parameters;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidSessionException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;
import software.sandc.springframework.security.jwt.model.exception.TokenRenewalException;
import software.sandc.springframework.security.jwt.model.exception.UserNotFoundException;
import software.sandc.springframework.security.jwt.util.RSAUtils;
import software.sandc.springframework.security.jwt.util.StringUtils;

public class DefaultJWTService implements JWTService, InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultJWTService.class);
    private static final Integer TEN_YEARS_IN_SECONDS = 315360000;

    public static final String SPRING_SECURITY_JWT_KEY_ID_PARAMETER_NAME = "kid";
    public static final String SPRING_SECURITY_JWT_SESSION_ID_PARAMETER_NAME = "jti";
    public static final String SPRING_SECURITY_JWT_XSRF_PARAMETER_NAME = "xsrf-token";
    public static final String SPRING_SECURITY_JWT_AUTHORITIES_PARAMETER_NAME = "authorities";

    protected UserDetailsService userDetailsService;
    protected JWTRequestResponseHandler jwtRequestResponseHandler;
    protected KeyProvider keyProvider;
    protected SigningKeyResolver signingKeyResolver;
    protected SessionProvider sessionProvider;
    protected UserDetailsChecker userDetailsChecker;
    protected String sessionIdParameterName = SPRING_SECURITY_JWT_SESSION_ID_PARAMETER_NAME;
    protected String xsrfParameterName = SPRING_SECURITY_JWT_XSRF_PARAMETER_NAME;
    protected String authoritiesParameterName = SPRING_SECURITY_JWT_AUTHORITIES_PARAMETER_NAME;
    protected int tokenLifetimeInSeconds = 600;
    protected int sessionInvalidationDelayInMinutes = 5;

    public DefaultJWTService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response) {
        JWTContext jwtContext = null;
        try {
            TokenContainer tokenContainer = jwtRequestResponseHandler.getTokenFromRequest(request);
            if (tokenContainer != null) {
                try {
                    Parameters parameters = jwtRequestResponseHandler.getParametersFromRequest(request);
                    jwtContext = validate(tokenContainer, parameters);
                } catch (ExpiredTokenException e) {
                    if (isTokenRenewalEnabled()) {
                        Parameters parameters = jwtRequestResponseHandler.getParametersFromRequest(request);
                        jwtContext = renew(tokenContainer, parameters);
                    }
                }
                handleJWTContext(request, response, jwtContext);
            }
        } catch (AuthenticationException e) {
            LOGGER.debug("Authentication failed for provided JWT token. " + e.getMessage());
        }
        return jwtContext;
    }

    public JWTContext authenticateLoginRequest(Credentials credentials, HttpServletRequest request,
            HttpServletResponse response) {
        JWTContext jwtContext = null;
        String password = credentials.getPassword();
        String principal = credentials.getPrincipal();
        if (principal != null && password != null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(principal);
            if (password.equals(userDetails.getPassword())) {
                Parameters parameters = jwtRequestResponseHandler.getParametersFromRequest(request);
                jwtContext = create(principal, parameters);
                handleJWTContext(request, response, jwtContext);
            }
        }
        return jwtContext;
    }

    public JWTContext createAndAttach(String principal, HttpServletRequest request, HttpServletResponse response,
            Parameters parameters) {
        JWTContext jwtContext = null;
        if (principal != null) {
            Parameters parametersFromRequest = jwtRequestResponseHandler.getParametersFromRequest(request);
            if (parametersFromRequest != null) {
                parametersFromRequest.merge(parameters);
                parameters = parametersFromRequest;
            }
            jwtContext = create(principal, parameters);
            handleJWTContext(request, response, jwtContext);
        }
        return jwtContext;
    }

    /**
     * Creates {@link JWTContext} for given principal. A {@link JWTContext}
     * contains all relevant tokens (like JWT or XSRF Tokens) and
     * {@link JWTAuthentication} object, which is relevant for Spring-Security.
     * 
     * @param principal
     *            Unique user identifier. This can be the user name or user id
     *            according to underlying implementation.
     * @return Fully fledged {@link JWTContext} object.
     * @throws UserNotFoundException
     *             if the user identified with given principal cannot be found.
     */
    public JWTContext create(String principal, Parameters parameters) throws UserNotFoundException {
        String keyId = keyProvider.getCurrentSigningKeyId();
        String signingKey = keyProvider.getPrivateKey(keyId);
        SignatureAlgorithm signatureAlgorithm = keyProvider.getSignatureAlgorithm(keyId);
        Date now = new Date();
        Date sessionExpiry = new Date(System.currentTimeMillis() + (tokenLifetimeInSeconds * 1000));
        String xsrfToken = null;
        if (!isXSRFProtectionDisabled(parameters)) {
            xsrfToken = generateXSRFToken();
        }
        UserDetails userDetails = getUserDetails(principal);
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        String authoritiesAsString = convertToString(authorities);

        Claims claims = Jwts.claims();
        if (xsrfToken != null) {
            claims.put(xsrfParameterName, xsrfToken);
        }
        claims.put(authoritiesParameterName, authoritiesAsString);
        String sessionId = null;
        if (sessionProvider != null) {
            sessionId = sessionProvider.createSession(principal);
            claims.put(sessionIdParameterName, sessionId);
        }

        JwtBuilder jwtBuilder = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).setClaims(claims)
                .setSubject(userDetails.getUsername()).setIssuedAt(now).setNotBefore(now).setExpiration(sessionExpiry);

        if (signatureAlgorithm.isHmac()) {
            byte[] binarySigningKey = TextCodec.BASE64.decode(signingKey);
            jwtBuilder = jwtBuilder.signWith(signatureAlgorithm, binarySigningKey);
        } else if (signatureAlgorithm.isRsa()) {
            PrivateKey privateKey = RSAUtils.toPrivateKey(signingKey);
            jwtBuilder = jwtBuilder.signWith(signatureAlgorithm, privateKey);
        } else {
            throw new UnsupportedJwtException("Not supported signature algorithm " + signatureAlgorithm.getValue());
        }

        String jwtToken = jwtBuilder.compact();
        JWTContext jwtContext = createJWTContext(principal, sessionId, xsrfToken, authorities, jwtToken);
        return jwtContext;
    }

    public JWTContext renew(TokenContainer tokenContainer, Parameters parameters) {
        if (sessionProvider == null) {
            throw new TokenRenewalException("No session provider found for token renewal.");
        }

        boolean ignoreExpiry = true;
        Parameters validationParameters = new Parameters(parameters);
        validationParameters.put(Parameters.KEY_IGNORE_EXPIRY, ignoreExpiry);
        validate(tokenContainer, validationParameters);

        JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver)
                .setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
        String jwtToken = tokenContainer.getJwtToken();
        Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
        Claims claims = jws.getBody();
        String sessionId = extractSessionId(claims);
        String principal = extractPrincipal(claims);

        if (sessionProvider.isSessionValid(sessionId)) {
            invalidateSession(principal, sessionId);
            return create(principal, parameters);
        } else {
            throw new InvalidSessionException("Token session does not exist or not valid anymore.");
        }
    }

    public JWTContext validate(TokenContainer tokenContainer, Parameters parameters)
            throws InvalidTokenException, ExpiredTokenException {
        if (tokenContainer == null) {
            throw new InvalidTokenException("Token container is empty");
        }
        JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver);
        if (parameters != null && parameters.isTrue(Parameters.KEY_IGNORE_EXPIRY)) {
            jwtParser = jwtParser.setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
        }
        String jwtToken = tokenContainer.getJwtToken();
        try {
            Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
            Claims claims = jws.getBody();
            String xsrfToken = tokenContainer.getXsrfToken();
            validateXSRF(claims, xsrfToken);
            String principal = extractPrincipal(claims);
            String sessionId = extractSessionId(claims);
            Collection<GrantedAuthority> authorities = getAuthorities(claims);
            JWTContext jwtContext = createJWTContext(principal, sessionId, xsrfToken, authorities, jwtToken);
            return jwtContext;
        } catch (ExpiredJwtException e) {
            throw new ExpiredTokenException("JWT Token is expired.");
        } catch (JwtException e) {
            throw new InvalidTokenException("JWT Token is invalid.", e);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        Assert.notNull(this.userDetailsService, "userDetailsService must be specified");

        if (jwtRequestResponseHandler == null) {
            jwtRequestResponseHandler = new DefaultJWTRequestResponseHandler();
        }

        if (keyProvider == null) {
            keyProvider = new FakeKeyProvider();
        }

        if (signingKeyResolver == null) {
            signingKeyResolver = new DefaultSigningKeyResolver(keyProvider);
        }

        if (sessionProvider == null) {
            sessionProvider = new FakeSessionProvider();
        }

        if (userDetailsChecker == null) {
            userDetailsChecker = new AccountStatusUserDetailsChecker();
        }

    }

    public boolean isTokenRenewalEnabled() {
        return sessionProvider != null;
    }

    public void setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        this.signingKeyResolver = signingKeyResolver;
    }

    public void setKeyProvider(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setJwtRequestResponseHandler(JWTRequestResponseHandler jwtRequestResponseHandler) {
        this.jwtRequestResponseHandler = jwtRequestResponseHandler;
    }

    public JWTRequestResponseHandler getJwtRequestResponseHandler() {
        return this.jwtRequestResponseHandler;
    }

    public void setSessionProvider(SessionProvider sessionProvider) {
        this.sessionProvider = sessionProvider;
    }

    public void setAuthoritiesParameterName(String authoritiesParameterName) {
        this.authoritiesParameterName = authoritiesParameterName;
    }

    public void setSessionIdParameterName(String sessionIdParameterName) {
        this.sessionIdParameterName = sessionIdParameterName;
    }

    public void setXsrfParameterName(String xsrfParameterName) {
        this.xsrfParameterName = xsrfParameterName;
    }

    /**
     * Set {@link UserDetailsChecker} which will be used to validate the loaded
     * <tt>UserDetails</tt> object.
     * 
     * @param userDetailsChecker
     *            An instance of user details checker implementation.
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
        Assert.notNull(userDetailsChecker, "userDetailsChacker cannot be null");
        this.userDetailsChecker = userDetailsChecker;
    }

    /**
     * Set token lifetime in seconds.
     * 
     * @param tokenLifetimeInSeconds
     *            Token lifetime in seconds.
     */
    public void setTokenLifetime(int tokenLifetimeInSeconds) {
        this.tokenLifetimeInSeconds = tokenLifetimeInSeconds;
    }

    /**
     * Set session invalidation delay in minutes.
     * 
     * @param sessionInvalidationDelayInMinutes
     *            Session invalidation delay in minutes.
     */
    public void setSessionInvalidationDelayInMinutes(int sessionInvalidationDelayInMinutes) {
        this.sessionInvalidationDelayInMinutes = sessionInvalidationDelayInMinutes;
    }

    public void invalidateSession(String principal, String sessionId) {
        if (sessionProvider != null) {
            sessionProvider.invalidateSessionAfterMinutes(sessionId, sessionInvalidationDelayInMinutes);
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

    protected JWTContext createJWTContext(String principal, String sessionId, String xsrfToken,
            Collection<? extends GrantedAuthority> authorities, String jwtToken) {
        TokenContainer tokenContainer = new TokenContainer(jwtToken, xsrfToken);
        JWTAuthentication authentication = new JWTAuthentication(principal, sessionId, authorities);
        JWTContext jwtContext = new JWTContext(authentication, tokenContainer);
        return jwtContext;
    }

    protected String generateXSRFToken() {
        return UUID.randomUUID().toString();
    }

    protected void validateXSRF(Claims claims, String xsrfToken) {
        String xsrfTokenFromClaim = claims.get(xsrfParameterName, String.class);
        if (xsrfTokenFromClaim != null && !xsrfTokenFromClaim.equals(xsrfToken)) {
            throw new InsufficientAuthenticationException("XSRF Token is not valid.");
        }
    }

    protected String convertToString(Collection<? extends GrantedAuthority> authorities) {
        List<String> authoriesAsStringList = getAuthorityListAsString(authorities);
        String authoritiesAsString = StringUtils.join(authoriesAsStringList, ",");
        return authoritiesAsString;
    }

    protected UserDetails getUserDetails(String principal) {
        try {
            UserDetails user = userDetailsService.loadUserByUsername(principal);
            userDetailsChecker.check(user);
            return user;
        } catch (UsernameNotFoundException e) {
            throw new UserNotFoundException("User with principal: " + principal + " cannot be found.", e);
        }
    }

    protected List<String> getAuthorityListAsString(Collection<? extends GrantedAuthority> authorities) {
        List<String> authoritiesAsString = new ArrayList<String>();
        if (authorities != null) {
            for (GrantedAuthority authority : authorities) {
                authoritiesAsString.add(authority.getAuthority());
            }
        }
        return authoritiesAsString;
    }

    protected void handleJWTContext(HttpServletRequest request, HttpServletResponse response, JWTContext jwtContext) {
        if (jwtContext != null && jwtContext.isAuthenticated()) {
            JWTAuthentication authentication = jwtContext.getAuthentication();
            SecurityContextHolder.getContext().setAuthentication(authentication);
            sessionProvider.refreshSession(authentication.getSessionId());
            jwtRequestResponseHandler.putTokenToResponse(request, response, jwtContext.getTokenContainer());
        }
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

    protected boolean isXSRFProtectionDisabled(Parameters parameters) {
        return parameters != null && parameters.isTrue(Parameters.KEY_DISABLE_XSRF_PROTECTION);
    }

}
