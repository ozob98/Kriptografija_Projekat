package user;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class User {

    private String username;
    private String password;
    private String name;
    private String lastname;
    private String email;
    private String phone;
    private X509Certificate userCertificate = null;
    private KeyPair userKeyPair = null;

    public User() {
    }

    public User(String username, String password, String name, String lastname, String email, String phone) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.lastname = lastname;
        this.email = email;
        this.phone = phone;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public X509Certificate getUserCertificate() {
        return userCertificate;
    }

    public void setUserCertificate(X509Certificate userCertificate) {
        this.userCertificate = userCertificate;
    }

    public KeyPair getUserKeyPair()
    {
        return userKeyPair;
    }

    public void setUserKeyPair(KeyPair userKeyPair)
    {
        this.userKeyPair = userKeyPair;
    }
    public void setUserToNull(){
        this.username = null;
        this.password = null;
        this.name = null;
        this.lastname = null;
        this.email = null;
        this.phone = null;
        this.userCertificate = null;
        this.userKeyPair = null;
    }

    @Override
    public String toString() {
        return "Username: "+ username + "\nName and lastname: " + name + " " + lastname + "\ne-mail: " + email + "\nPhone: " + phone;
    }
}
