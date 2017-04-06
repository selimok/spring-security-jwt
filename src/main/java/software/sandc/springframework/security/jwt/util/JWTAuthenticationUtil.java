package software.sandc.springframework.security.jwt.util;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import software.sandc.springframework.security.jwt.model.JWTAuthentication;

public class JWTAuthenticationUtil {

    public static String getCurrentUserId(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null){            
            Object principal = authentication.getPrincipal();
            if(principal != null){
                return String.valueOf(principal);
            }
        }
        return null;
    }
    
    public static Collection<? extends GrantedAuthority> getCurrentUserAuthorities(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null){            
             return authentication.getAuthorities();
        }
        return null;
    }
    
    public static String getCurrentUserSessionId(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null && authentication instanceof JWTAuthentication){
            JWTAuthentication jwtAuthentication = (JWTAuthentication)authentication;
            return jwtAuthentication.getSessionId();
        }
        return null;
    }
}
