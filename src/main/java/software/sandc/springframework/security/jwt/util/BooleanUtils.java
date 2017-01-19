package software.sandc.springframework.security.jwt.util;

public class BooleanUtils {

    /**
     * Check if given Boolean value is true. This method is Null-safe.
     * 
     * @param value
     *            Boolean value. Can be null.
     * @return <b>true</b> when given value is not null and true.
     */
    public static Boolean isTrue(Boolean value) {
        return value != null && value == true;
    }
    
    /**
     * Check if given Boolean value is false. This method is Null-safe.
     * 
     * @param value
     *            Boolean value. Can be null.
     * @return <b>true</b> when given value is not null and false.
     */
    public static Boolean isFalse(Boolean value) {
        return value != null && value == false;
    }
}
