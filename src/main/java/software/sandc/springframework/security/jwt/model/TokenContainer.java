package software.sandc.springframework.security.jwt.model;

public class TokenContainer {

	private String jwtToken;
	private String xsrfToken;

	
	public TokenContainer(String jwtToken) {
		this.jwtToken = jwtToken;
	}
	
	public TokenContainer(String jwtToken, String xsrfToken) {
		this.jwtToken = jwtToken;
		this.xsrfToken = xsrfToken;
	}

	public String getJwtToken() {
		return jwtToken;
	}

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
