package software.sandc.springframework.security.jwt.model;

/**
 * {@link TokenContainer} is a container class for JWT and XSRF tokens. A
 * {@link TokenContainer} must at least contain a non-empty JWT token value.
 * 
 * @author selimok
 */
public class TokenContainer {

    private String jwtToken;
    private String xsrfToken;

    /**
     * Create a {@link TokenContainer} instance with given JWT token.
     * 
     * @param jwtToken
     *            JWT token value as String.
     */
    public TokenContainer(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    /**
     * Create a {@link TokenContainer} instance with given JWT and XSRF tokens.
     * 
     * @param jwtToken
     *            JWT token value as String.
     * @param xsrfToken
     *            XSRF token value as String.
     */
    public TokenContainer(String jwtToken, String xsrfToken) {
        this.jwtToken = jwtToken;
        this.xsrfToken = xsrfToken;
    }

    /**
     * Get JWT token.
     * 
     * @return JWT token value as String.
     */
    public String getJwtToken() {
        return jwtToken;
    }

    /**
     * Get XSRF token.
     * 
     * @return XSRF token value as String.
     */
    public String getXsrfToken() {
        return xsrfToken;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((jwtToken == null) ? 0 : jwtToken.hashCode());
        result = prime * result + ((xsrfToken == null) ? 0 : xsrfToken.hashCode());
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
        TokenContainer other = (TokenContainer) obj;
        if (jwtToken == null) {
            if (other.jwtToken != null)
                return false;
        } else if (!jwtToken.equals(other.jwtToken))
            return false;
        if (xsrfToken == null) {
            if (other.xsrfToken != null)
                return false;
        } else if (!xsrfToken.equals(other.xsrfToken))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "TokenContainer [jwtToken=" + jwtToken + ", xsrfToken=" + xsrfToken + "]";
    }

}
