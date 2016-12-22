
package software.sandc.springframework.security.jwt.util;

public class StringUtils {

    public static String join(final Iterable<String> iterable, String separator) {
	StringBuilder stringBuilder = new StringBuilder();

	if (iterable != null) {
	    if (separator == null) {
		separator = "";
	    }
	    boolean first = true;
	    for (String item : iterable) {
		if (first) {
		    stringBuilder.append(item);
		} else {
		    stringBuilder.append(separator).append(item);
		}
		first = false;
	    }
	}

	return stringBuilder.toString();
    }

}
