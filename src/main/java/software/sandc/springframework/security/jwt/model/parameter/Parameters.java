package software.sandc.springframework.security.jwt.model.parameter;

import java.util.HashMap;
import java.util.Map;

/**
 * Additional parameters to customize processing of the request. Possible parameters and their effects may differ
 * depending on specific implementation.
 * 
 * @author selimok
 *
 */
@SuppressWarnings("rawtypes")
public class Parameters {

    private Map<Class<? extends Parameter>, Parameter<?>> parameterMap;

    public Parameters() {
        this.parameterMap = new HashMap<Class<? extends Parameter>, Parameter<?>>();
    }

    public <T> Parameters(Parameter<?> parameter) {
        this.parameterMap = new HashMap<Class<? extends Parameter>, Parameter<?>>();
        put(parameter);
    }

    public Parameters(Parameters parameters) {
        if (parameters != null && parameters.getParameterMap() != null) {
            this.parameterMap = parameters.getParameterMap();
        } else {
            this.parameterMap = new HashMap<Class<? extends Parameter>, Parameter<?>>();
        }
    }

    /**
     * Merge given parameters into existing parameters. Given parameters overwrites existing parameters, if their keys
     * are equal.
     * 
     * @param parametersToMerge
     *            {@link Parameters} to merge.
     */
    public void merge(Parameters parametersToMerge) {
        if (parametersToMerge != null) {
            Map<Class<? extends Parameter>, Parameter<?>> parameterMapToMerge = parametersToMerge.getParameterMap();
            if (parameterMapToMerge != null) {
                this.parameterMap.putAll(parameterMapToMerge);
            }
        }
    }

    public <T> void put(Parameter<T> parameter) {
        parameterMap.put(parameter.getClass(), parameter);
    }

    public void remove(Class<? extends Parameter> parameterType) {
        parameterMap.remove(parameterType);
    }

    @SuppressWarnings("unchecked")
    public <T> T getValueOf(Class<? extends Parameter<T>> parameterType) {
        Parameter<?> parameter = parameterMap.get(parameterType);
        if (parameter != null && parameter.getValue() != null) {
            return ((T) parameter.getValue());
        } else {
            return null;
        }
    }

    protected Map<Class<? extends Parameter>, Parameter<?>> getParameterMap() {
        return this.parameterMap;
    }

}
