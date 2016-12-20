package software.sandc.springframework.security.jwt.model;

/**
 * {@link JWTContext} is a container class for {@link JWTAuthentication} and
 * {@link TokenContainer} instances.
 * 
 * @author selimok
 */
public class JWTContext {

    private JWTAuthentication authentication;
    private TokenContainer tokenContainer;

    /**
     * Create an empty {@link JWTContext} instance.
     */
    public JWTContext() {
    }

    /**
     * Create a {@link JWTContext} instance with given {@link JWTAuthentication}
     * and {@link TokenContainer} instances.
     * 
     * @param authentication
     *            {@link JWTAuthentication} instance
     * @param tokenContainer
     *            {@link TokenContainer} instance
     */
    public JWTContext(JWTAuthentication authentication, TokenContainer tokenContainer) {
	this.authentication = authentication;
	this.tokenContainer = tokenContainer;
    }

    /**
     * Get {@link JWTAuthentication} instance from context.
     * 
     * @return {@link JWTAuthentication} instance.
     */
    public JWTAuthentication getAuthentication() {
	return authentication;
    }

    /**
     * Set {@link JWTAuthentication} instance into context.
     * 
     * @param authentication
     *            {@link JWTAuthentication} instance.
     */
    public void setAuthentication(JWTAuthentication authentication) {
	this.authentication = authentication;
    }

    /**
     * Get {@link TokenContainer} instance from context.
     * 
     * @return {@link TokenContainer} instance.
     */
    public TokenContainer getTokenContainer() {
	return tokenContainer;
    }

    /**
     * Set {@link TokenContainer} instance into context.
     * 
     * @param tokenContainer
     *            {@link TokenContainer} instance.
     */
    public void setTokenContainer(TokenContainer tokenContainer) {
	this.tokenContainer = tokenContainer;
    }

    /**
     * Checks if {@link JWTAuthentication} from context exists and is
     * authenticated.
     * 
     * @return <b>true</b> if {@link JWTAuthentication} from context exists and
     *         is authenticated.
     */
    public boolean isAuthenticated() {
	return authentication != null && authentication.isAuthenticated();
    }

    @Override
    public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + ((authentication == null) ? 0 : authentication.hashCode());
	result = prime * result + ((tokenContainer == null) ? 0 : tokenContainer.hashCode());
	return result;
    }

    @Override
    public boolean equals(Object obj) {
	if (this == obj)
	    return true;
	if (obj == null)
	    return false;
	if (getClass() != obj.getClass())
	    return false;
	JWTContext other = (JWTContext) obj;
	if (authentication == null) {
	    if (other.authentication != null)
		return false;
	} else if (!authentication.equals(other.authentication))
	    return false;
	if (tokenContainer == null) {
	    if (other.tokenContainer != null)
		return false;
	} else if (!tokenContainer.equals(other.tokenContainer))
	    return false;
	return true;
    }

    @Override
    public String toString() {
	return "JWTContext [authentication=" + authentication + ", tokenContainer=" + tokenContainer + "]";
    }

}
