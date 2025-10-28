package security.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import user.User;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class RSAKey {

    private static final int KEY_SIZE = 2048;
    private static final String KEY_ALGORITHM = "RSA";
    private static final String CA_KEY_PATH = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\certificates\\CA\\cakey.pem";

    public static KeyPair generateRSAKeyPair() throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, "BC");
            kpGen.initialize(KEY_SIZE, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch(Exception e){
            throw new Exception("Error while generating RSA key",e);
        }
    }

    public static KeyPair getKeyPairFromStore(String username, String password, KeyStore keyStore) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(username, password.toCharArray());
        Certificate cert = keyStore.getCertificate(username);
        X509Certificate x509Cert = (X509Certificate) cert;
        PublicKey publicKey = x509Cert.getPublicKey();
        return new KeyPair(publicKey,privateKey);
    }

    public static void writeUserPrivateKey(User user) throws Exception {

        FileWriter fw = new FileWriter(user.getUsername()+"Key.pem");
        JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
        pemWriter.writeObject(user.getUserKeyPair().getPrivate());
        pemWriter.close();
        fw.close();
    }

    public static PrivateKey getCAPrivateKey() throws IOException
    {
        Security.addProvider(new BouncyCastleProvider());
        PEMParser pemParser = new PEMParser(new FileReader(CA_KEY_PATH));
        PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey cakey = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        pemParser.close();
        return cakey;
    }

}
