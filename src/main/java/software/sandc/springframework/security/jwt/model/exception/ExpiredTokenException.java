package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if the token is expired.
 * 
 * @author selimok
 *
 */
public class ExpiredTokenException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a {@link ExpiredTokenException} with the specified message.
     *
     * @param msg
     *            the detail message
     */
    public ExpiredTokenException(String msg) {
        super(msg);
    }

    /**
     * Constructs a {@link ExpiredTokenException} with the specified message and
     * root cause.
     *
     * @param msg
     *            the detail message
     * @param t
     *            root cause
     */
    public ExpiredTokenException(String msg, Throwable t) {
        super(msg, t);
    }

}
