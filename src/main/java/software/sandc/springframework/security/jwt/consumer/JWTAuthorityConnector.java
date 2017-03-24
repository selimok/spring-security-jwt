package software.sandc.springframework.security.jwt.consumer;

import javax.servlet.http.HttpServletRequest;

import software.sandc.springframework.security.jwt.model.JWTContext;

public interface JWTAuthorityConnector extends KeyProvider{
    
    public JWTContext requestRenew(HttpServletRequest originalRequest);
    
}
