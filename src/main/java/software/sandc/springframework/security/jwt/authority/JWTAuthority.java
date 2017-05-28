package software.sandc.springframework.security.jwt.authority;

import java.security.PrivateKey;
import java.util.ArrayList;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;
import software.sandc.springframework.security.jwt.JWTRequestResponseHandler;
import software.sandc.springframework.security.jwt.consumer.JWTConsumer;
import software.sandc.springframework.security.jwt.impl.DefaultSigningKeyResolver;
import software.sandc.springframework.security.jwt.impl.authority.FakeKeyProvider;
import software.sandc.springframework.security.jwt.impl.authority.FakeSessionProvider;
import software.sandc.springframework.security.jwt.model.Credentials;
import software.sandc.springframework.security.jwt.model.JWTAuthentication;
import software.sandc.springframework.security.jwt.model.JWTContext;
import software.sandc.springframework.security.jwt.model.TokenContainer;
import software.sandc.springframework.security.jwt.model.exception.ExpiredTokenException;
import software.sandc.springframework.security.jwt.model.exception.InvalidSessionException;
import software.sandc.springframework.security.jwt.model.exception.TokenRenewalException;
import software.sandc.springframework.security.jwt.model.exception.UserNotFoundException;
import software.sandc.springframework.security.jwt.model.parameter.DisableXSRFParameter;
import software.sandc.springframework.security.jwt.model.parameter.IgnoreExpiryParameter;
import software.sandc.springframework.security.jwt.model.parameter.Parameters;
import software.sandc.springframework.security.jwt.model.parameter.SessionIdParameter;
import software.sandc.springframework.security.jwt.util.BooleanUtils;
import software.sandc.springframework.security.jwt.util.RSAUtils;
import software.sandc.springframework.security.jwt.util.StringUtils;

public class JWTAuthority extends JWTConsumer implements InitializingBean {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthority.class);

    protected UserDetailsService userDetailsService;
    protected SessionProvider sessionProvider;
    protected UserDetailsChecker userDetailsChecker;
    protected int tokenLifetimeInSeconds = 600;
    protected int sessionInvalidationDelayInMinutes = 5;
    protected PasswordEncoder passwordEncoder;
    protected AuthorityKeyProvider authorityKeyProvider;

    public JWTAuthority(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public JWTContext authenticateJWTRequest(HttpServletRequest request, HttpServletResponse response) {
        JWTContext jwtContext = null;
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
            refreshSession(jwtContext);
            handleJWTContext(request, response, jwtContext);
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
            if (passwordEncoder.matches(password, userDetails.getPassword())) {
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
        if (parameters == null) {
            parameters = new Parameters();
        }
        String keyId = authorityKeyProvider.getCurrentSigningKeyId();
        String signingKey = authorityKeyProvider.getPrivateKey(keyId);
        SignatureAlgorithm signatureAlgorithm = authorityKeyProvider.getSignatureAlgorithm(keyId);
        Date now = new Date();
        Date sessionExpiry = new Date(System.currentTimeMillis() + (tokenLifetimeInSeconds * 1000));
        String xsrfToken = null;
        if (!isXSRFProtectionDisabled(parameters)) {
            LOGGER.trace("XSRF protection is enabled. Creating XSRF Token.");
            xsrfToken = generateXSRFToken();
        }else{
            LOGGER.trace("XSRF protection is disabled. Skipping XSRF Token generation");
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
            sessionId = parameters.getValueOf(SessionIdParameter.class);

            if (sessionId == null || sessionId.isEmpty()) {
                sessionId = sessionProvider.createSession(principal);
            }

            if (sessionId != null && !sessionId.isEmpty()) {
                claims.put(sessionIdParameterName, sessionId);
            }
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
        String jwtMode = getJWTModeFromParameters(parameters);
        JWTContext jwtContext = createJWTContext(principal, sessionId, xsrfToken, authorities, jwtMode, jwtToken);
        return jwtContext;
    }

    public JWTContext renew(HttpServletRequest request, HttpServletResponse response) {
        JWTContext jwtContext = null;
        TokenContainer tokenContainer = jwtRequestResponseHandler.getTokenFromRequest(request);
        if (tokenContainer != null) {
            Parameters parameters = jwtRequestResponseHandler.getParametersFromRequest(request);
            jwtContext = renew(tokenContainer, parameters);
            refreshSession(jwtContext);
            handleJWTContext(request, response, jwtContext);
        }
        return jwtContext;
    }

    public JWTContext renew(TokenContainer tokenContainer, Parameters parameters) {
        if (sessionProvider == null) {
            throw new TokenRenewalException("No session provider found for token renewal.");
        }

        boolean ignoreExpiry = true;
        Parameters renewParameters = new Parameters(parameters);
        renewParameters.put(new IgnoreExpiryParameter(ignoreExpiry));
        validate(tokenContainer, renewParameters);

        JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(signingKeyResolver)
                .setAllowedClockSkewSeconds(TEN_YEARS_IN_SECONDS);
        String jwtToken = tokenContainer.getJwtToken();
        Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
        Claims claims = jws.getBody();
        String sessionId = extractSessionId(claims);
        String principal = extractPrincipal(claims);

        if (sessionProvider.isSessionValid(sessionId)) {
            String renewedSessionId = sessionProvider.renewSession(sessionId);
            renewParameters.put(new SessionIdParameter(renewedSessionId));
            JWTContext jwtContext = create(principal, parameters);
            return jwtContext;
        } else {
            throw new InvalidSessionException("Token session does not exist or not valid anymore.");
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        Assert.notNull(this.userDetailsService, "userDetailsService must be specified");

        if (jwtRequestResponseHandler == null) {
            jwtRequestResponseHandler = new JWTRequestResponseHandler();
        }

        if (authorityKeyProvider == null) {
            authorityKeyProvider = new FakeKeyProvider();
        }

        if (signingKeyResolver == null) {
            signingKeyResolver = new DefaultSigningKeyResolver(authorityKeyProvider);
        }

        if (sessionProvider == null) {
            sessionProvider = new FakeSessionProvider();
        }

        if (userDetailsChecker == null) {
            userDetailsChecker = new AccountStatusUserDetailsChecker();
        }

        if (passwordEncoder == null) {
            passwordEncoder = new BCryptPasswordEncoder();
        }

    }

    public boolean isTokenRenewalEnabled() {
        return sessionProvider != null;
    }

    public UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setSessionProvider(SessionProvider sessionProvider) {
        this.sessionProvider = sessionProvider;
    }

    public void setAuthorityKeyProvider(AuthorityKeyProvider authorityKeyProvider) {
        this.authorityKeyProvider = authorityKeyProvider;
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
    public void setTokenLifetimeInSeconds(int tokenLifetimeInSeconds) {
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

    /**
     * Set custom password encoder.
     * 
     * @param passwordEncoder
     *            Password encoder
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }

    public UserDetailsChecker getUserDetailsChecker() {
        return userDetailsChecker;
    }

    public int getTokenLifetimeInSeconds() {
        return tokenLifetimeInSeconds;
    }

    public int getSessionInvalidationDelayInMinutes() {
        return sessionInvalidationDelayInMinutes;
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public AuthorityKeyProvider getAuthorityKeyProvider() {
        return authorityKeyProvider;
    }

    protected String generateXSRFToken() {
        return UUID.randomUUID().toString();
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

    protected void refreshSession(JWTContext jwtContext) {
        if (jwtContext != null && jwtContext.isAuthenticated() && sessionProvider != null) {
            JWTAuthentication authentication = jwtContext.getAuthentication();
            sessionProvider.refreshSession(authentication.getSessionId());
        }
    }

    protected void handleJWTContext(HttpServletRequest request, HttpServletResponse response, JWTContext jwtContext) {
        if (jwtContext != null && jwtContext.isAuthenticated()) {
            JWTAuthentication authentication = jwtContext.getAuthentication();
            SecurityContextHolder.getContext().setAuthentication(authentication);
            jwtRequestResponseHandler.putTokenToResponse(request, response, jwtContext.getTokenContainer());
        }
    }

    protected boolean isXSRFProtectionDisabled(Parameters parameters) {
        if (parameters != null) {
            Boolean isXSRFProtectionDisabled = parameters.getValueOf(DisableXSRFParameter.class);
            return BooleanUtils.isTrue(isXSRFProtectionDisabled);
        } else {
            return false;
        }
    }

}
