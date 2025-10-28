package user;

import security.encryption.Password;
import validators.*;

import java.util.Scanner;

public class UserReader {

    private static final Scanner SCANNER = new Scanner(System.in);

    private EmailValidator emailValidator = new EmailValidator();
    private NameValidator nameValidator = new NameValidator();
    private PasswordValidator passwordValidator = new PasswordValidator();
    private PhoneValidator phoneValidator = new PhoneValidator();
    private UsernameValidator usernameValidator = new UsernameValidator();

    public String readEmail(){
        String email = "";
        do{
            System.out.println("Enter your email address: ");
            email = SCANNER.nextLine();
        } while(!emailValidator.validate(email));

        return email;
    }
    public String readName(){
        String name="";
        do{
            System.out.println("Enter your name: ");
            name = SCANNER.nextLine();
        }while(!nameValidator.validate(name));

        return name;
    }
    public String readLastname(){
        String lastname="";
        do{
            System.out.println("Enter your lastname: ");
            lastname = SCANNER.nextLine();
        }while(!nameValidator.validate(lastname));

        return lastname;
    }
    public String readPassword(){
        String password="";
        do{
            System.out.println("Enter your password: ");
            password = SCANNER.nextLine();
        }while(!passwordValidator.validate(password));

        password = Password.securePassword(password);
        //mozda base64 kodovati

        return  password;
    }
    public String readPhone(){
        String phone="";
        do{
            System.out.println("Enter your phone number: ");
            phone = SCANNER.nextLine();
        }while(!phoneValidator.validate(phone));

        return phone;
    }
    public String readUsername(){
        String username="";
        do{
            System.out.println("Enter your username: ");
            username = SCANNER.nextLine();
        }while(!usernameValidator.validate(username));

        return username;
    }
}
