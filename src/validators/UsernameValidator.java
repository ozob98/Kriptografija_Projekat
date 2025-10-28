package validators;

import user.UserDBService;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class UsernameValidator implements Validate{

    private static final String USERNAME_PATTERN ="^[a-zA-Z0-9]{3,20}$";

    @Override
    public boolean validate(String username){
        Pattern pattern = Pattern.compile(USERNAME_PATTERN);
        Matcher matcher = pattern.matcher(username);
        if(!matcher.matches()){
            System.out.println("Username can be consisted of lower case letters, upper case letters and numbers only. ");
            return false;
        }
        else{
            if(UserDBService.userExists(username)){
                System.out.println("Username already exists!");
                return false;
            }
            return true;
        }
    }
}
