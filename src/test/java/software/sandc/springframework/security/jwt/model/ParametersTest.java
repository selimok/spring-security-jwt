package software.sandc.springframework.security.jwt.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;

public class ParametersTest {
    
    private Parameters parameters;
    
    @Before
    public void init(){
	parameters = new Parameters();
    }
    
    @Test
    public void shouldReturnExpectedBooleanValue() throws Exception {
        //given
        String key = "key";
        Boolean expectedValue = true;
        parameters.put(key, expectedValue);
    
        //when
        Boolean value = parameters.getBoolean(key);
        
        //then
        assertEquals(expectedValue, value);
    }

    @Test
    public void shouldReturnExpectedBooleanValueWhenValueIsPrimitiv() throws Exception {
	
	// given
	String key = "key";
	boolean expectedValue = true;
	parameters.put(key, expectedValue);

	//when
	Boolean value = parameters.getBoolean(key);
	
	//then
	assertEquals(expectedValue, value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedBooleanValueIsInteger() throws Exception {
	//given
	String key = "key";
	parameters.put(key, 2);
	
	//when
	Boolean value = parameters.getBoolean(key);
	
	//then
	assertNull(value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedBooleanValueIsString() throws Exception {
	//given
	String key = "key";
	parameters.put(key, "true");
	
	//when
	Boolean value = parameters.getBoolean(key);
	
	//then
	assertNull(value);
    }

    
    @Test
    public void shouldReturnExpectedIntegerValue() throws Exception {
        //given
        String key = "key";
        Integer expectedValue = 5123;
        parameters.put(key, expectedValue);
    
        //when
        Integer value = parameters.getInteger(key);
        
        //then
        assertEquals(expectedValue, value);
    }

    @Test
    public void shouldReturnExpectedIntegerValueWhenValueIsPrimitiv() throws Exception {
	
	// given
	String key = "key";
	int expectedValue = 5123;
	parameters.put(key, expectedValue);

	//when
	Integer value = parameters.getInteger(key);
	
	//then
	assertEquals(Integer.valueOf(expectedValue), value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedIntegerValueIsBoolean() throws Exception {
	//given
	String key = "key";
	parameters.put(key, true);
	
	//when
	Integer value = parameters.getInteger(key);
	
	//then
	assertNull(value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedIntegerValueIsString() throws Exception {
	//given
	String key = "key";
	parameters.put(key, "true");
	
	//when
	Integer value = parameters.getInteger(key);
	
	//then
	assertNull(value);
    }
    
    @Test
    public void shouldReturnExpectedStringValue() throws Exception {
        //given
        String key = "key";
        String expectedValue = "hello";
        parameters.put(key, expectedValue);
    
        //when
        String value = parameters.getString(key);
        
        //then
        assertEquals(expectedValue, value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedStringValueIsBoolean() throws Exception {
	//given
	String key = "key";
	parameters.put(key, true);
	
	//when
	String value = parameters.getString(key);
	
	//then
	assertNull(value);
    }
    
    @Test
    public void shouldReturnNullValueWhenExpectedStringValueIsInteger() throws Exception {
	//given
	String key = "key";
	parameters.put(key, 2);
	
	//when
	String value = parameters.getString(key);
	
	//then
	assertNull(value);
    }

}
