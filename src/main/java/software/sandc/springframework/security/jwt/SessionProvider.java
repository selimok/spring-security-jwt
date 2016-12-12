package software.sandc.springframework.security.jwt;

public interface SessionProvider {

	public String createSession(String principal);
	
	public boolean isSessionValid(String sessionId);
	
	public void invalidateSession(String sessionId);
	
}
