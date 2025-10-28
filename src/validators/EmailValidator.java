package validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
public class EmailValidator implements Validate {
    private static final String EMAIL_PATTERN = "^[a-zA-Z0-9]+(?:\\.[a-zA-Z0-9]+)*@(?:[a-zA-Z0-9]+\\.)+[a-zA-Z]{2,6}$";

    @Override
    public boolean validate(String email){
        Pattern pattern = Pattern.compile(EMAIL_PATTERN);
        Matcher matcher = pattern.matcher(email);

        if(!matcher.matches()){
            System.out.println("Invalid email. ");
            return false;
        }
        else{
            return true;
        }
    }
}
