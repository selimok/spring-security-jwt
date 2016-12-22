package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if token is not valid.
 * 
 * @author selimok
 *
 */
public class InvalidTokenException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a {@link InvalidTokenException} with the specified message.
     *
     * @param msg
     *            the detail message
     */
    public InvalidTokenException(String msg) {
        super(msg);
    }

    /**
     * Constructs a {@link InvalidTokenException} with the specified message and
     * root cause.
     *
     * @param msg
     *            the detail message
     * @param t
     *            root cause
     */
    public InvalidTokenException(String msg, Throwable t) {
        super(msg, t);
    }

}
