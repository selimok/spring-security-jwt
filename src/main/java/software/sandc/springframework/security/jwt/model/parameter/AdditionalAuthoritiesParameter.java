package software.sandc.springframework.security.jwt.model.parameter;

import java.util.List;

public class AdditionalAuthoritiesParameter extends AbstractParameter<List<String>> {

    public AdditionalAuthoritiesParameter(List<String> value) {
        super(value);
    }

}
