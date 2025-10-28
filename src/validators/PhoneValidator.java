package validators;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class PhoneValidator implements Validate{

    private static final String PHONE_PATTERN ="^\\d{9}$";

    @Override
    public boolean validate(String phone){
        Pattern pattern = Pattern.compile(PHONE_PATTERN);
        Matcher matcher = pattern.matcher(phone);

        if(!matcher.matches()){
            System.out.println("Phone number must have 9 digits.");
            return false;
        }
        else{
            return true;
        }
    }
}
