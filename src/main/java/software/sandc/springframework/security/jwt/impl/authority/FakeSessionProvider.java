package software.sandc.springframework.security.jwt.impl.authority;

import java.util.UUID;

import software.sandc.springframework.security.jwt.authority.SessionProvider;

public class FakeSessionProvider implements SessionProvider {

    public String createSession(String principal) {
        return UUID.randomUUID().toString();
    }

    public boolean isSessionValid(String sessionId) {
        return true;
    }

    public void invalidateSession(String sessionId) {
        // Do nothing
    }

    @Override
    public void refreshSession(String sessionId) {
        // Do nothing
    }

    @Override
    public void removeSession(String sessionId) {
        // Do nothing
    }

    @Override
    public String renewSession(String sessionId) {
        // Do nothing
        return null;
    }

}
