package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if the wanted user cannot be found. 
 * 
 * @author selimok
 *
 */
public class UserNotFoundException extends AuthenticationException {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a {@link UserNotFoundException} with the
	 * specified message.
	 *
	 * @param msg
	 *            the detail message
	 */
	public UserNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a {@link UserNotFoundException} with the
	 * specified message and root cause.
	 *
	 * @param msg
	 *            the detail message
	 * @param t
	 *            root cause
	 */
	public UserNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}


}
