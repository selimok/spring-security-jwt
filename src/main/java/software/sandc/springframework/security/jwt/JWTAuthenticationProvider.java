package software.sandc.springframework.security.jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;

public class JWTAuthenticationProvider implements AuthenticationProvider, InitializingBean, EnvironmentAware {

	private Environment environment;

	public static final String SPRING_SECURITY_JWT_SESSION_ID_KEY = "jwtSessionId";
	public static final String SPRING_SECURITY_JWT_XSRF_KEY = "xsrf-token";
	public static final String SPRING_SECURITY_JWT_AUTHORITIES_KEY = "authorities";

	protected UserDetailsService userDetailsService;
	protected SigningKeyResolver signingKeyResolver;
	protected SigningKeyProvider signingKeyProvider;
	protected SessionProvider sessionProvider = new EmptySessionProvider();
	protected UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	protected SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
	protected String sessionIdParameter = SPRING_SECURITY_JWT_SESSION_ID_KEY;
	protected String xsrfParameter = SPRING_SECURITY_JWT_XSRF_KEY;
	protected String authoritiesParameter = SPRING_SECURITY_JWT_AUTHORITIES_KEY;
	protected Boolean jwtCompressionEnabled = false;
	protected int sessionTimeout = 600;

	public JWTAuthenticationProvider(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		JWTAuthenticationToken jwtAuthenticationToken = (JWTAuthenticationToken) authentication;
		if (jwtAuthenticationToken.isAuthenticated()) {
			// User is pre-authenticated we should create a new JWT token for
			// this user.

			if (jwtAuthenticationToken.getPrincipal() == null) {
				throw new BadCredentialsException("Provided Authentication object does not contains principal.");
			}

			String principal = jwtAuthenticationToken.getPrincipal().toString();
			Object details = jwtAuthenticationToken.getDetails();

			jwtAuthenticationToken = createJWTTokenForPrincipal(principal, null);
			jwtAuthenticationToken.setDetails(details);
		} else {

			String jwtToken = jwtAuthenticationToken.getJwtToken();
			String xsrfToken = jwtAuthenticationToken.getXsrfToken();

			if (jwtToken != null && !jwtToken.isEmpty()) {
				JwtParser jwtParser = Jwts.parser().ignoreExpiry();
				if (signingKeyResolver != null) {
					jwtParser = jwtParser.setSigningKeyResolver(signingKeyResolver);
				} else {
					jwtParser = jwtParser.setSigningKey(
							DatatypeConverter.parseBase64Binary(signingKeyProvider.getCurrentSigningKeyId()));
				}

				Jws<Claims> jws = jwtParser.parseClaimsJws(jwtToken);
				Claims claims = jws.getBody();

				validateXSRF(claims, xsrfToken);

				boolean expired = jwtParser.isExpired(jwtToken);

				if (expired) {
					// Renew token if renewable
					String principal = claims.getSubject();
					if (principal == null) {
						throw new BadCredentialsException("Provided JWT Token does not contains principal.");
					}

					String sessionId = claims.get(SPRING_SECURITY_JWT_SESSION_ID_KEY, String.class);

					boolean sessionValid = sessionProvider.isSessionValid(sessionId);
					if (sessionValid) {
						jwtAuthenticationToken = createJWTTokenForPrincipal(principal, sessionId);
					} else {
						throw new CredentialsExpiredException(
								"JWT Token is expired and claimed session id is invalid. JWT token cannot be renewed.");
					}

				}
			}
		}

		return jwtAuthenticationToken;
	}

	/**
	 * Indicate that this provider supports {@link JWTAuthenticationToken} or
	 * {@link UsernamePasswordAuthenticationToken} (sub)classes.
	 */
	public final boolean supports(Class<?> authentication) {
		return JWTAuthenticationToken.class.isAssignableFrom(authentication);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(userDetailsService, "userDetailsService must be specified");
		if (signingKeyProvider == null) {
			signingKeyProvider = new DefaultSigningKeyProvider(environment);
		}
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;

	}

	public void setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
		this.signingKeyResolver = signingKeyResolver;
	}

	public void setSigningKeyProvider(SigningKeyProvider signingKeyProvider) {
		this.signingKeyProvider = signingKeyProvider;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public void setSessionProvider(SessionProvider sessionProvider) {
		this.sessionProvider = sessionProvider;
	}

	/**
	 * TODO: Set parameter name for session id.
	 * 
	 * @param sessionIdParameter
	 */
	public void setSessionIdParameter(String sessionIdParameter) {
		this.sessionIdParameter = sessionIdParameter;
	}

	/**
	 * TODO: Set parameter name for xsrf token.
	 * 
	 * @param xsrfParameter
	 */
	public void setXsrfParameter(String xsrfParameter) {
		this.xsrfParameter = xsrfParameter;
	}

	/**
	 * Sets the strategy which will be used to validate the loaded
	 * <tt>UserDetails</tt> object for the user. Defaults to an
	 * {@link AccountStatusUserDetailsChecker}.
	 * 
	 * @param userDetailsChecker
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		Assert.notNull(userDetailsChecker, "userDetailsChacker cannot be null");
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Set session timeout in seconds.
	 * 
	 * @param sessionTimeout
	 */
	public void setSessionTimeout(int sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}

	/**
	 * 
	 * @param authoritiesParameter
	 */
	public void setAuthoritiesParameter(String authoritiesParameter) {
		this.authoritiesParameter = authoritiesParameter;
	}

	/**
	 * 
	 * @param signatureAlgorithm
	 */
	public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	protected void validateXSRF(Claims claims, String xsrfToken) {
		String xsrfTokenFromClaim = claims.get(xsrfParameter, String.class);

		if (StringUtils.isBlank(xsrfToken) || StringUtils.isBlank(xsrfTokenFromClaim)
				|| !StringUtils.equals(xsrfToken, xsrfTokenFromClaim)) {
			throw new InsufficientAuthenticationException("XSRF Token is not valid.");
		}

	}

	protected String createJWTTokenForUser(UserDetails user, String xsrfToken, String sessionId) {
		String keyId = signingKeyProvider.getCurrentSigningKeyId();
		String signingKey = signingKeyProvider.getSigningKey(keyId);
		byte[] binarySigningKey = DatatypeConverter.parseBase64Binary(signingKey);

		Date now = new Date();
		Date sessionExpiry = new Date(System.currentTimeMillis() + (sessionTimeout * 60 * 1000));

		Claims claims = Jwts.claims();

		claims.put(xsrfParameter, xsrfToken);

		Collection<? extends GrantedAuthority> authorityList = user.getAuthorities();
		List<String> authorityListAsString = getAuthorityListAsString(authorityList);
		String authorities = StringUtils.join(authorityListAsString, ',');
		claims.put(authoritiesParameter, authorities);

		claims.put(sessionIdParameter, sessionId);

		JwtBuilder jwtBuilder = Jwts.builder().setHeaderParam("kid", keyId).setClaims(claims)
				.setSubject(user.getUsername()).setIssuedAt(now).setNotBefore(now).setExpiration(sessionExpiry)
				.signWith(signatureAlgorithm, binarySigningKey);
		if (jwtCompressionEnabled) {
			jwtBuilder.compressWith(CompressionCodecs.DEFLATE);
		}

		String token = jwtBuilder.compact();

		return token;
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

	private JWTAuthenticationToken createJWTTokenForPrincipal(String principal, String sessionId) {
		UserDetails user = getUserDetails(principal);

		if (sessionId == null) {
			sessionId = sessionProvider.createSession(user.getUsername());
		}

		String xsrfToken = UUID.randomUUID().toString();

		String jwtToken = createJWTTokenForUser(user, xsrfToken, sessionId);
		JWTAuthenticationToken jwtAuthenticationToken = new JWTAuthenticationToken(user.getUsername(), jwtToken,
				sessionId, user.getAuthorities());
		return jwtAuthenticationToken;
	}

	private UserDetails getUserDetails(String principal) {
		UserDetails user = userDetailsService.loadUserByUsername(principal);

		if (user == null) {
			throw new UsernameNotFoundException(String.format("User with principal: %s cannot be found.", principal));
		}

		userDetailsChecker.check(user);
		return user;
	}

}
