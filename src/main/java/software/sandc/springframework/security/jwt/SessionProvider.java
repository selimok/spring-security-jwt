package software.sandc.springframework.security.jwt;

public interface SessionProvider {

	String createSession(String username);
	
	boolean isSessionValid(String sessionId);
	
	void invalidateSession(String sessionId);
	
}
