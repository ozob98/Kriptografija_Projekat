package security.encryption;


import org.bouncycastle.util.encoders.Hex;
import user.User;

import java.security.*;
import java.util.*;

public class Password {
    private static final int SALT_LENGTH = 16;
    private static final String HASH_ALGORITHM = "SHA-256";
    public static String securePassword(String password)  {
        try {
            byte[] salt = generateSalt();
            byte[] hashedPassword = hashPassword(password, salt, HASH_ALGORITHM);
            String s = Hex.toHexString(salt);
            String hp = Hex.toHexString(hashedPassword);
            return s + ":" + hp;
        }catch(NoSuchAlgorithmException e){
            throw new RuntimeException("Error hashing password", e);
        }
    }

    public static boolean validatePassword(User user, String password) {
        try {
            String[] separatePasswordUser = user.getPassword().split(":");
            byte[] saltUser = Hex.decode(separatePasswordUser[0]);
            byte[] hashPasswordUser = Hex.decode(separatePasswordUser[1]);
            byte[] hashPasswordLogin = hashPassword(password,saltUser,HASH_ALGORITHM);
            if(MessageDigest.isEqual(hashPasswordUser,hashPasswordLogin))
            {
                return true;
            }
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
       return false;
    }
    private static byte[] generateSalt(){
        byte[] salt = new byte[SALT_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    private static byte[] hashPassword(String password, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(salt);
        return md.digest(password.getBytes());
    }
}
