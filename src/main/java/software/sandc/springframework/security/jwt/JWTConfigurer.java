package software.sandc.springframework.security.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;

public class JWTConfigurer<B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<JWTConfigurer<B>, B> {

	private JWTRequestResponseHandler jwtRequestResponseHandler;

	public JWTConfigurer<B> jwtRequestResponseHandler(JWTRequestResponseHandler jwtRequestResponseHandler)
			throws Exception {
		this.jwtRequestResponseHandler = jwtRequestResponseHandler;
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

		JWTAuthenticationFilter jwtAuthenticationFilter = new JWTAuthenticationFilter(authenticationManager);

		if (jwtRequestResponseHandler != null) {
			jwtAuthenticationFilter.setJwtRequestResponseHandler(jwtRequestResponseHandler);
		}

		jwtAuthenticationFilter = postProcess(jwtAuthenticationFilter);
		http.addFilterAfter(jwtAuthenticationFilter, SwitchUserFilter.class);
	}

}