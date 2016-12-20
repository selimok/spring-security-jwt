package software.sandc.springframework.security.jwt.model;

/**
 * {@link Credentials} class contains principal (unique user identifier like
 * user name, user id, email address etc.) and password data which are needed
 * for user authentication.
 * 
 * @author selimok
 */
public class Credentials {

    private String principal;
    private String password;

    /**
     * Get principal (unique user identifier like user name, user id, email
     * address etc.)
     * 
     * @return Principal as String.
     */
    public String getPrincipal() {
	return principal;
    }

    /**
     * Set principal (unique user identifier like user name, user id, email
     * address etc.)
     * 
     * @param principal
     *            Principal as String.
     */
    public void setPrincipal(String principal) {
	this.principal = principal;
    }

    /**
     * Get password in clear text.
     * 
     * @return Passwort in clear text.
     */
    public String getPassword() {
	return password;
    }

    /**
     * Set password in clear text.
     * @param password Passwort in clear text.
     */
    public void setPassword(String password) {
	this.password = password;
    }

    @Override
    public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + ((password == null) ? 0 : password.hashCode());
	result = prime * result + ((principal == null) ? 0 : principal.hashCode());
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
	Credentials other = (Credentials) obj;
	if (password == null) {
	    if (other.password != null)
		return false;
	} else if (!password.equals(other.password))
	    return false;
	if (principal == null) {
	    if (other.principal != null)
		return false;
	} else if (!principal.equals(other.principal))
	    return false;
	return true;
    }

    @Override
    public String toString() {
	return "Credentials [principal=" + principal + ", password=[PROTECTED]]";
    }

}
