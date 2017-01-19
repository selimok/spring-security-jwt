package software.sandc.springframework.security.jwt.model.parameter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import software.sandc.springframework.security.jwt.model.parameter.DisableXSRFParameter;

public class ParametersTest {

    private Parameters parameters;

    @Before
    public void init() {
        parameters = new Parameters();
    }

    @Test
    public void shouldReturnTrue() throws Exception {
        // given
        parameters.put(new DisableXSRFParameter(true));

        // when
        Boolean value = parameters.getValueOf(DisableXSRFParameter.class);

        // then
        assertTrue(value);
    }

    @Test
    public void shouldReturnFalse() throws Exception {

        // given
        parameters.put(new DisableXSRFParameter(false));

        // when
        Boolean value = parameters.getValueOf(DisableXSRFParameter.class);

        // then
        assertFalse(value);
    }

    @Test
    public void shouldReturnNull() throws Exception {

        // given

        // when
        Boolean value = parameters.getValueOf(DisableXSRFParameter.class);

        // then
        assertNull(value);
    }

}
