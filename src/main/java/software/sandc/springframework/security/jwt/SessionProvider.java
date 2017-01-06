package software.sandc.springframework.security.jwt;

/**
 * {@link SessionProvider} is used only if a JWT token is linked to a session to
 * increase token security. <br>
 * <br>
 * Conventional JWT tokens have an expiration date and should be renewed if the
 * token expires. To avoid frequent re-login each time if the token expires,
 * developers sets commonly quasi infinite expiration dates or renew tokens
 * without any re-authentication steps. These approaches increases security
 * risks, especially against token stealing.<br>
 * <br>
 * So called sessions can be used to store JWT validity state and can be checked
 * every time when a token must be renewed. In this way a token can have a
 * shorter expiration cycle (e.g. 15 minutes) and can be revoked if it is
 * stolen. As long as the linked session is not revoked by user or
 * administrators, expired JWT tokens can be renewed without any (user involved)
 * re-authentication step.<br>
 * <br>
 * The responsibility of a {@link SessionProvider} implementation is create and
 * store a session for a given principal (any unique user identifier like user
 * id, user name, email address, etc.), check if given session id is valid or
 * not, and invalidate a session if needed. <br>
 * <br>
 * A session entry must have at least following data: session id, principal,
 * validity flag. But a particular {@link SessionProvider} may provide or store
 * more information in session storage.
 * 
 * @author selimok
 *
 */
public interface SessionProvider {

    /**
     * Creates and stores a new session for given principal.
     * 
     * @param principal
     *            Any unique user identifier like user id, user name, email
     *            address, etc.
     * @return Unique session id of created session
     */
    public String createSession(String principal);

    /**
     * Checks if the given session (referenced by session id) valid.
     * 
     * @param sessionId
     *            Unique session id.
     * @return <b>true</b> if session is valid, <b>false</b> if it's revoked and
     *         not valid anymore.
     */
    public boolean isSessionValid(String sessionId);

    /**
     * Revokes given session (referenced by session id).
     * 
     * @param sessionId
     *            Unique session id.
     */
    public void invalidateSession(String sessionId);

    /**
     * Revokes given session (referenced by session id) with delay.
     *
     * @param sessionId
     *            Unique session id.
     * @param minutes Delay in minutes
     */
    public void invalidateSessionAfterMinutes(String sessionId, Integer minutes);

    /**
     * Refreshes given session (referenced by session id). Depending on the
     * implementation this method may refresh session related data like last
     * touch time, ip address, agent details etc.
     * 
     * @param sessionId
     *            Unique session id.
     */
    public void refreshSession(String sessionId);

    /**
     * Remove given session (referenced by session id).
     * 
     * @param sessionId
     *            Unique session id.
     */
    public void removeSession(String sessionId);
}
