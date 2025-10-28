package validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordValidator implements Validate{

    private static final String PASSWORD_PATTERN ="((?=.*\\d)(?=.*[A-Z])(?=.*\\W).{5,15})";

    @Override
    public boolean validate(String password){
        Pattern pattern = Pattern.compile(PASSWORD_PATTERN);
        Matcher matcher = pattern.matcher(password);

        if(!matcher.matches()){
            System.out.println("Password must contain at least one lower case and one bigger case letter, special character and a number. ");
            return false;
        }
        else{
            return true;
        }
    }
}
