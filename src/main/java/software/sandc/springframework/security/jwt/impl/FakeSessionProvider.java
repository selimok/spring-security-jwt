package software.sandc.springframework.security.jwt.impl;

import java.util.UUID;

import software.sandc.springframework.security.jwt.SessionProvider;

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
    public void invalidateSessionAfterMinutes(String sessionId, Integer minutes) {
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

}
