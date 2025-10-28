package registrationlogin;

import security.certificate.Certificate;
import security.encryption.RSAKey;
import user.User;
import user.UserDBService;
import user.UserFileService;
import user.UserReader;

import java.security.KeyPair;
import java.security.cert.X509Certificate;


public class Registration {

  private static UserReader userReader = new UserReader();

  public void registerUser() {

    User newUser = new User();
    //username
    String username = userReader.readUsername();
    newUser.setUsername(username);
    //password
    String password = userReader.readPassword();
    newUser.setPassword(password);
    //name and lastname
    String name = userReader.readName();
    newUser.setName(name);
    String lastname = userReader.readLastname();
    newUser.setLastname(lastname);
    //email
    String mail = userReader.readEmail();
    newUser.setEmail(mail);
    //phone
    String phone = userReader.readPhone();
    newUser.setPhone(phone);

    try {
      //kreiramo kljuc i sertifikat
      KeyPair userKeyPair = RSAKey.generateRSAKeyPair();
      X509Certificate userCer = Certificate.createUserCertificate(newUser, userKeyPair.getPublic());
      //setujemo kljuc i sertifikat
      newUser.setUserKeyPair(userKeyPair);
      newUser.setUserCertificate(userCer);
      //kreiramo PKCS12 i upisujemo korisnika u bazu
      Certificate.createUserPKCS12(newUser);
      UserDBService.writeUser(newUser);
      UserFileService.makeUserRepository(newUser);
    } catch (Exception e) {
      System.out.println(e.getMessage());
      //e.printStackTrace();
    }
  }
}
