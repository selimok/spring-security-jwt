package software.sandc.springframework.security.jwt.model;

import java.util.HashMap;
import java.util.Map;

public class Parameters {

    public static final String KEY_IGNORE_EXPIRY = "ignoreExpiry";
    public static final String KEY_DISABLE_XSRF_PROTECTION = "disableXSRFProtection";
    public static final String KEY_SESSION_ID = "sessionId";

    protected Map<String, Object> parameterMap;

    public Parameters() {
        this.parameterMap = new HashMap<String, Object>();
    }

    public Parameters(String key, Object value) {
        this.parameterMap = new HashMap<String, Object>();
        this.parameterMap.put(key, value);
    }

    public Parameters(Parameters parameters) {
        if (parameters != null && parameters.getParameterMap() != null) {
            this.parameterMap = parameters.getParameterMap();
        } else {
            this.parameterMap = new HashMap<String, Object>();
        }
    }

    public Parameters(Map<String, Object> parameterMap) {
        if (parameterMap != null) {
            this.parameterMap = parameterMap;
        } else {
            this.parameterMap = new HashMap<String, Object>();
        }
    }

    /**
     * Merge given parameters into existing parameters. Given parameters
     * overwrites existing parameters, if their keys are equal.
     * 
     * @param parametersToMerge
     *            {@link Parameters} to merge.
     */
    public void merge(Parameters parametersToMerge) {
        if (parametersToMerge != null) {
            Map<String, Object> parameterMapToMerge = parametersToMerge.getParameterMap();
            if (parameterMapToMerge != null) {
                this.parameterMap.putAll(parameterMapToMerge);
            }
        }
    }

    public void put(String key, Object value) {
        parameterMap.put(key, value);
    }

    public void remove(String key) {
        parameterMap.remove(key);
    }

    public Boolean isTrue(String key) {
        Boolean value = getBoolean(key);
        if (value != null) {
            return value;
        } else {
            return false;
        }

    }

    public Boolean getBoolean(String key) {
        return get(key, Boolean.class);
    }

    public Integer getInteger(String key) {
        return get(key, Integer.class);
    }

    public String getString(String key) {
        return get(key, String.class);
    }

    public <T> T get(String key, Class<T> type) {
        Object object = parameterMap.get(key);

        if (object != null) {
            try {
                return type.cast(object);
            } catch (ClassCastException e) {
                // Do nothing
            }
        }
        return null;

    }

    public Map<String, Object> getParameterMap() {
        return this.parameterMap;
    }

}
