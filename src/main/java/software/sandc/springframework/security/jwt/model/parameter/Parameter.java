package software.sandc.springframework.security.jwt.model.parameter;

/**
 * A parameter can be used to customize processing of the request.
 * 
 * @author selimok
 *
 * @param <T>
 */
public interface Parameter<T> {

    public T getValue();

}
