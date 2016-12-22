package software.sandc.springframework.security.jwt.util;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class StringUtilsTest {

    @Test
    public void shouldJoinStringListWithMultipleElements() throws Exception {
        //given
        String elem1 = "hello";
        String elem2 = "hello2";
        String elem3 = "hello3";
        List<String> stringList = createList(elem1, elem2, elem3);
        
        // when
        String joinedString = StringUtils.join(stringList, ",");
    
        //then
        assertEquals("hello,hello2,hello3", joinedString);
    }
    
    @Test
    public void shouldJoinStringListWithMultipleElementsWithNullSeparator() throws Exception {
        //given
        String elem1 = "hello";
        String elem2 = "hello2";
        String elem3 = "hello3";
        List<String> stringList = createList(elem1, elem2, elem3);
        
        // when
        String joinedString = StringUtils.join(stringList, null);
    
        //then
        assertEquals("hellohello2hello3", joinedString);
    }
    
    @Test
    public void shouldJoinStringListWithSingleElement() throws Exception {
        //given
        String elem1 = "hello";
        List<String> stringList = createList(elem1);
        
        // when
        String joinedString = StringUtils.join(stringList, ",");
    
        //then
        assertEquals("hello", joinedString);
    }
    
    @Test
    public void shouldJoinStringListWithoutAnyElements() throws Exception {
        //given
        List<String> stringList = createList();
        
        // when
        String joinedString = StringUtils.join(stringList, ",");
    
        //then
        assertEquals("", joinedString);
    }

    
    
    private List<String> createList(String... elements) {
	List<String> stringList = new ArrayList<String>();
	for(String element : elements){
	    stringList.add(element);
	}
	return stringList;
    }
}
