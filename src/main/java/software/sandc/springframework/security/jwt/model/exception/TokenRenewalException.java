package software.sandc.springframework.security.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if token cannot be renewed.
 * 
 * @author selimok
 *
 */
public class TokenRenewalException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a {@link TokenRenewalException} with the
	 * specified message.
	 *
	 * @param msg
	 *            the detail message
	 */
	public TokenRenewalException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a {@link TokenRenewalException} with the
	 * specified message and root cause.
	 *
	 * @param msg
	 *            the detail message
	 * @param t
	 *            root cause
	 */
	public TokenRenewalException(String msg, Throwable t) {
		super(msg, t);
	}

}
