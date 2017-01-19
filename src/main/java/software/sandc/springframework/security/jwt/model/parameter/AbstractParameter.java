package software.sandc.springframework.security.jwt.model.parameter;

public abstract class AbstractParameter<T> implements Parameter<T> {

    private T value;

    
    public AbstractParameter(T value){
        this.value = value;
    }
    
    public T getValue() {
        return this.value;
    }

}
