package software.sandc.springframework.security.jwt;

import java.util.UUID;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.util.Assert;

public class DefaultSigningKeyProvider implements SigningKeyProvider, InitializingBean {

	private Environment environment;

	public DefaultSigningKeyProvider(Environment environment) {
		this.environment = environment;
	}

	@Override
	public String getCurrentSigningKeyId() {
		return UUID.randomUUID().toString();
	}

	@Override
	public String getSigningKey(String keyId) {
		return environment.getProperty("security.jwt.secret.key");
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(environment, "environment must be specified");
	}

}
