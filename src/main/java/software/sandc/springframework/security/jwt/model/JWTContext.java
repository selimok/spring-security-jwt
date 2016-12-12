package software.sandc.springframework.security.jwt.model;

public class JWTContext {

	private JWTAuthentication authentication;
	private TokenContainer tokenContainer;

	
	public JWTContext(){
	}
	
	public JWTContext(JWTAuthentication authentication, TokenContainer tokenContainer){
		this.authentication = authentication;
		this.tokenContainer = tokenContainer;
	}
	
	public JWTAuthentication getAuthentication() {
		return authentication;
	}

	public void setAuthentication(JWTAuthentication authentication) {
		this.authentication = authentication;
	}

	public TokenContainer getTokenContainer() {
		return tokenContainer;
	}

	public void setTokenContainer(TokenContainer tokenContainer) {
		this.tokenContainer = tokenContainer;
	}

	public boolean isAuthenticated(){
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
