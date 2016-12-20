package software.sandc.springframework.security.jwt.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

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
import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.JWTService;
import software.sandc.springframework.security.jwt.KeyProvider;
import software.sandc.springframework.security.jwt.SessionProvider;
import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidSessionException;
import software.sandc.springframework.security.jwt.model.exception.InvalidTokenException;
import software.sandc.springframework.security.jwt.model.exception.TokenRenewalException;
import software.sandc.springframework.security.jwt.util.StringUtils;

public class DefaultJWTService implements JWTService, InitializingBean {

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
    protected int tokenLifetime = 600;

    public DefaultJWTService(UserDetailsService userDetailsService) {
	this.userDetailsService = userDetailsService;
    }

    public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response) {
	JWTContext jwtContext = null;
	try {
	    TokenContainer tokenContainer = jwtRequestResponseHandler.getTokenFromRequest(request);
	    if (tokenContainer != null) {
		try {
		    jwtContext = validate(tokenContainer);
		} catch (ExpiredTokenException e) {
		    if (isTokenRenewalEnabled()) {
			jwtContext = renew(tokenContainer);
		    }
		}
		handleJWTContext(request, response, jwtContext);
	    }
	} catch (AuthenticationException e) {
	    // TODO: Log but do nothing else.
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
		jwtContext = create(principal);
		handleJWTContext(request, response, jwtContext);
	    }
	}
	return jwtContext;
    }

    public JWTContext createAndAttach(String principal, HttpServletRequest request, HttpServletResponse response) {
	JWTContext jwtContext = null;
	if (principal != null) {
	    jwtContext = create(principal);
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
     */
    public JWTContext create(String principal) {
	String keyId = keyProvider.getCurrentSigningKeyId();
	String signingKey = keyProvider.getPrivateKey(keyId);
	SignatureAlgorithm signatureAlgorithm = keyProvider.getSignatureAlgorithm(keyId);
	byte[] binarySigningKey = DatatypeConverter.parseBase64Binary(signingKey);
	Date now = new Date();
	Date sessionExpiry = new Date(System.currentTimeMillis() + (tokenLifetime * 1000));
	String xsrfToken = generateXSRFToken();
	UserDetails userDetails = getUserDetails(principal);
	Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
	String authoritiesAsString = convertToString(authorities);

	Claims claims = Jwts.claims();
	claims.put(xsrfParameterName, xsrfToken);
	claims.put(authoritiesParameterName, authoritiesAsString);
	if (sessionProvider != null) {
	    claims.put(sessionIdParameterName, sessionProvider.createSession(principal));
	}

	JwtBuilder jwtBuilder = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).setClaims(claims)
		.setSubject(userDetails.getUsername()).setIssuedAt(now).setNotBefore(now).setExpiration(sessionExpiry)
		.signWith(signatureAlgorithm, binarySigningKey);
	String jwtToken = jwtBuilder.compact();

	JWTContext jwtContext = createJWTContext(principal, xsrfToken, authorities, jwtToken);

	return jwtContext;
    }

    public JWTContext renew(TokenContainer tokenContainer) {
	if (sessionProvider == null) {
	    throw new TokenRenewalException("No session provider found for token renewal.");
	}

	boolean ignoreExpiry = true;
	validate(tokenContainer, ignoreExpiry);

	JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver)
		.setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
	String jwtToken = tokenContainer.getJwtToken();
	Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
	Claims claims = jws.getBody();
	String sessionId = getSessionId(claims);
	String principal = getPrincipal(claims);

	if (sessionProvider.isSessionValid(sessionId)) {
	    return create(principal);
	} else {
	    throw new InvalidSessionException("Token session does not exist or not valid anymore.");
	}
    }

    public JWTContext validate(TokenContainer tokenContainer) throws InvalidTokenException, ExpiredTokenException {
	return validate(tokenContainer, false);
    }

    public JWTContext validate(TokenContainer tokenContainer, boolean ignoreExpiry)
	    throws InvalidTokenException, ExpiredTokenException {
	if (tokenContainer == null) {
	    throw new InvalidTokenException("Token container is empty");
	}
	JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver);
	if (ignoreExpiry) {
	    jwtParser = jwtParser.setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
	}
	String jwtToken = tokenContainer.getJwtToken();
	try {
	    Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
	    Claims claims = jws.getBody();
	    String xsrfToken = tokenContainer.getXsrfToken();
	    validateXSRF(claims, xsrfToken);
	    String principal = getPrincipal(claims);
	    Collection<GrantedAuthority> authorities = getAuthorities(claims);
	    JWTContext jwtContext = createJWTContext(principal, xsrfToken, authorities, jwtToken);
	    return jwtContext;
	} catch (ExpiredJwtException e) {
	    throw new ExpiredTokenException("JWT Token is expired.");
	} catch (JwtException e) {
	    throw new InvalidTokenException("JWT Token is invalid.", e);
	}
    }

    protected String getPrincipal(Claims claims) {
	String principal = claims.getSubject();

	if (principal == null || principal.isEmpty()) {
	    throw new InvalidTokenException("A valid token must provide a non-empty principal value.");
	}

	return principal;
    }

    protected String getSessionId(Claims claims) {
	String sessionId = claims.get(sessionIdParameterName, String.class);
	return sessionId;
    }

    private void handleJWTContext(HttpServletRequest request, HttpServletResponse response, JWTContext jwtContext) {
	if (jwtContext != null && jwtContext.isAuthenticated()) {
	    JWTAuthentication authentication = jwtContext.getAuthentication();
	    SecurityContextHolder.getContext().setAuthentication(authentication);
	    jwtRequestResponseHandler.putTokenToResponse(request, response, jwtContext.getTokenContainer());
	}
    }

    private Collection<GrantedAuthority> getAuthorities(Claims claims) {
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

    public boolean isTokenRenewalEnabled() {
	return sessionProvider != null;
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
     * @param tokenLifetime
     *            Token lifetime in seconds.
     */
    public void setTokenLifetime(int tokenLifetime) {
	this.tokenLifetime = tokenLifetime;
    }

    protected JWTContext createJWTContext(String principal, String xsrfToken,
	    Collection<? extends GrantedAuthority> authorities, String jwtToken) {
	TokenContainer tokenContainer = new TokenContainer(jwtToken, xsrfToken);
	JWTAuthentication authentication = new JWTAuthentication(principal, authorities);
	JWTContext jwtContext = new JWTContext(authentication, tokenContainer);
	return jwtContext;
    }

    protected String generateXSRFToken() {
	return UUID.randomUUID().toString();
    }

    protected void validateXSRF(Claims claims, String xsrfToken) {
	String xsrfTokenFromClaim = claims.get(xsrfParameterName, String.class);

	if (StringUtils.isBlank(xsrfToken) || StringUtils.isBlank(xsrfTokenFromClaim)
		|| !xsrfToken.equals(xsrfTokenFromClaim)) {
	    throw new InsufficientAuthenticationException("XSRF Token is not valid.");
	}
    }

    protected String convertToString(Collection<? extends GrantedAuthority> authorities) {
	List<String> authoriesAsStringList = getAuthorityListAsString(authorities);
	String authoritiesAsString = StringUtils.join(authoriesAsStringList, ',');
	return authoritiesAsString;
    }

    protected UserDetails getUserDetails(String principal) {
	UserDetails user = userDetailsService.loadUserByUsername(principal);

	if (user == null) {
	    throw new UsernameNotFoundException(String.format("User with principal: %s cannot be found.", principal));
	}

	userDetailsChecker.check(user);
	return user;
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

}
