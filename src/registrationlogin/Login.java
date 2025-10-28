package registrationlogin;

import menu.Menu;
import security.certificate.Certificate;
import security.encryption.RSAKey;
import user.UserDBService;
import user.User;
import validators.PKCS12PathValidator;
import validators.PasswordValidator;
import validators.UserValidator;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import static security.certificate.Certificate.*;

public class Login {
    public boolean logged = false;
    public int loginAttempts = 3;
    public boolean certificateSuspended = false;
    public User loggedUser = new User();
    private UserValidator userValidator = new UserValidator();
    private PasswordValidator passwordValidator = new PasswordValidator();
    private PKCS12PathValidator pkcs12PathValidator = new PKCS12PathValidator();
    private static final Scanner SCANNER = new Scanner(System.in);
    public void loginUser() {

        try {

            String filePath = "";
            do {
                System.out.println("Enter your PKCS12 file path: ");
                filePath = SCANNER.nextLine();
            } while (!pkcs12PathValidator.validate(filePath));

            String pkcs12Password = "";
            do {
                System.out.println("Enter your password for the PKCS12 file: ");
                pkcs12Password = SCANNER.nextLine();
            } while (!passwordValidator.validate(pkcs12Password));

            System.out.println("Reading PKCS12 keystore...");
            KeyStore keyStore = readPKCS12(filePath, pkcs12Password);

            //uzimamo sertifikat iz keystor-a
            System.out.println("Certificate validation...");
            X509Certificate cert = getUserCertificateFromPKCS12(keyStore);

            //provjera da li je sertifikat validan (datum na sertifikatu i da li je potpisan od CA kojeg treba)
            if (Certificate.certificateIsValid(cert)) {

                //verifikacija da digitalni sertifikat nije povucen
                if (Certificate.isRevoked(cert)) {
                    System.out.println("Certificate is suspended! Enter username and password to reactivate:");
                    certificateSuspended = true;
                    loginAttempts = 1;
                }

                while (loginAttempts>0) {

                    System.out.println("Enter your username: ");
                    String username = SCANNER.nextLine();
                    System.out.println("Enter your password: ");
                    String password = SCANNER.nextLine();

                    if (userValidator.validate(username, password, cert)) {
                        loggedUser = UserDBService.getUser(username);
                        loggedUser.setUserCertificate(cert);
                        loggedUser.setUserKeyPair(RSAKey.getKeyPairFromStore(username, password, keyStore));
                        logged = true;
                        loginAttempts = 0;
                    }
                    else{
                        loginAttempts-=1;
                        System.out.println("You have " + loginAttempts + " attempts.");
                    }
                }
                if(logged)
                {
                    if(certificateSuspended)
                    {
                        Certificate.removeFromCRL(convertX509Certificate(cert));
                        System.out.println("Certificate is no longer suspended");
                    }
                    System.out.println("Successful login! User: " + loggedUser.getUsername());
                }
                else {
                    if (certificateSuspended) {
                        System.out.println("Certificate will stay suspended.");
                    } else {
                        System.out.println("Unsuccessful login! Your certificate will be suspended. ");
                        if (Certificate.crlExists()) {
                            Certificate.updateCRL(convertX509Certificate(cert));
                        } else {
                            Certificate.createCRL(cert);
                        }
                    }
                    Menu.showMainMenu();
                }
            } else {
                System.out.println("Certificate not valid!");
                Menu.showMainMenu();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
            Menu.showMainMenu();
        }
    }

    public void restoreLogin(){
        this.loginAttempts = 3;
        this.certificateSuspended = false;
    }
}
