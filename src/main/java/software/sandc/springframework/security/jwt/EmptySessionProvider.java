package software.sandc.springframework.security.jwt;

public class EmptySessionProvider implements SessionProvider {

	public String createSession(String username) {
		return null;
	}

	public boolean isSessionValid(String sessionId) {
		return true;
	}

	public void invalidateSession(String sessionId) {
		// Do nothing
	}

}
