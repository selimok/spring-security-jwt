package software.sandc.springframework.security.jwt.util;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import software.sandc.springframework.security.jwt.model.JWTAuthentication;

public class JWTAuthenticationUtil {

    /**
     * Get user id if the user authenticated.
     * 
     * @return Unique user id (principal) if the user authenticated with a valid JWT Token
     *         (non-anonymous), null otherwise.
     */
    public static String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof JWTAuthentication && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal != null) {
                return String.valueOf(principal);
            }
        }
        return null;
    }

    /**
     * Get authorities of the authenticated user.
     * 
     * @return Authorities of the current user if the user authenticated with a valid JWT Token
     *         (non-anonymous), null otherwise.
     */
    public static Collection<? extends GrantedAuthority> getCurrentUserAuthorities() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof JWTAuthentication && authentication.isAuthenticated()) {
            return authentication.getAuthorities();
        }
        return null;
    }

    /**
     * Get session id of the JWT token if the user authenticated.
     * 
     * @return Session id if the user authenticated with a valid JWT Token and if the
     *         token bound to a session.
     */
    public static String getCurrentUserSessionId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof JWTAuthentication) {
            JWTAuthentication jwtAuthentication = (JWTAuthentication) authentication;
            return jwtAuthentication.getSessionId();
        }
        return null;
    }
}
