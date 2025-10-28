package validators;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import security.certificate.Certificate;
import user.UserDBService;
import security.encryption.Password;
import user.User;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class UserValidator {


    public boolean validate(String username, String password, X509Certificate userCertificateToValidate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {

        if(userExists(username)){
            User user = UserDBService.getUser(username);
            if(Password.validatePassword(user, password)){
                //provjera username
                X500Name x500name = new JcaX509CertificateHolder(userCertificateToValidate).getSubject();
                RDN cn = x500name.getRDNs(BCStyle.CN)[0];
                String commonName = IETFUtils.valueToString(cn.getFirst().getValue());
                if(!username.equals(commonName)){
                    System.out.println("Username and certificate do not match!");
                }
                else {
                    X509Certificate existingUserCertificate = Certificate.getUserCertificate(username);
                    if(!Objects.isNull(existingUserCertificate)) {
                        return existingUserCertificate.getPublicKey().equals(userCertificateToValidate.getPublicKey());
                    }
                }
            }
            else{
                System.out.println("Password incorrect");
            }
            return false;
        }
        System.out.println("Username does not exist");
        return false;
    }

    public boolean userExists(String username) {
        for (User user : UserDBService.readUsers()) {
            if (username.equals(user.getUsername())) return true;
        }
        return false;
    }
}
