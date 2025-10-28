package validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NameValidator implements Validate{

    private static final String NAME_PATTERN = "^[a-zA-Z]{3,20}$";

    @Override
    public boolean validate(String name){
        Pattern pattern = Pattern.compile(NAME_PATTERN);
        Matcher matcher = pattern.matcher(name);

        if(!matcher.matches()){
            System.out.println("Invalid name format. Must have 3-20 letters.");
            return false;
        }
        else{
            return true;
        }
    }
}
