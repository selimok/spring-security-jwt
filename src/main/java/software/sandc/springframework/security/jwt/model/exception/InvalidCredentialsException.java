package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if the credentials are invalid.
 * 
 * @author selimok
 *
 */
public class InvalidCredentialsException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a {@link InvalidCredentialsException} with the specified
     * message.
     *
     * @param msg
     *            the detail message
     */
    public InvalidCredentialsException(String msg) {
        super(msg);
    }

    /**
     * Constructs a {@link InvalidCredentialsException} with the specified
     * message and root cause.
     *
     * @param msg
     *            the detail message
     * @param t
     *            root cause
     */
    public InvalidCredentialsException(String msg, Throwable t) {
        super(msg, t);
    }

}
