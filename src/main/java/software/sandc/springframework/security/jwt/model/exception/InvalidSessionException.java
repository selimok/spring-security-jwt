package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if the linked session does not exist or is not valid anymore. 
 * 
 * @author selimok
 *
 */
public class InvalidSessionException extends AuthenticationException {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a {@link InvalidSessionException} with the
	 * specified message.
	 *
	 * @param msg
	 *            the detail message
	 */
	public InvalidSessionException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a {@link InvalidSessionException} with the
	 * specified message and root cause.
	 *
	 * @param msg
	 *            the detail message
	 * @param t
	 *            root cause
	 */
	public InvalidSessionException(String msg, Throwable t) {
		super(msg, t);
	}


}
