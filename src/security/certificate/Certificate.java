package security.certificate;


import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import security.encryption.Password;
import security.encryption.RSAKey;
import user.User;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static security.encryption.RSAKey.getCAPrivateKey;

public class Certificate {

  private static final Scanner SCANNER = new Scanner(System.in);
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final String CA_CERTIFICATE_PATH = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\certificates\\CA\\cacert.pem";
  private static final String CRL_PATH = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\certificates\\crl\\";
  private static final String USERS_CERTIFICATES_PATH = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\certificates\\users\\";
  private static final int ONE_MONTH_IN_HOURS = 730;
  private static long serialNumberBase = System.currentTimeMillis();

  public static synchronized BigInteger calculateSerialNumber() {
    return BigInteger.valueOf(serialNumberBase++);
  }

  public static Date calculateDate(int hoursInFuture) {
    long secs = System.currentTimeMillis() / 1000;
    return new Date((secs + ((long) (hoursInFuture) * 60 * 60)) * 1000);
  }

  public static X509Certificate convertX509CertificateHolder(X509CertificateHolder certHolder)
      throws GeneralSecurityException {
    Security.addProvider(new BouncyCastleProvider());
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
  }

  public static X509CertificateHolder convertX509Certificate(X509Certificate cert)
      throws CertificateException {
    Security.addProvider(new BouncyCastleProvider());
    return new JcaX509CertificateHolder(cert);
  }

  public static X509CertificateHolder getCACertificate() throws IOException, CertificateException {
    FileInputStream fis = new FileInputStream(CA_CERTIFICATE_PATH);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
    X509CertificateHolder cacert = new JcaX509CertificateHolder(certificate);
    fis.close();
    return cacert;
  }

  public static X509Certificate createUserCertificate(User user, PublicKey userKey)
      throws Exception {

    try {
      X509CertificateHolder CACert = getCACertificate();
      PrivateKey CAKey = RSAKey.getCAPrivateKey();

      X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
          .addRDN(BCStyle.C, "BA")
          .addRDN(BCStyle.ST, "BL")
          .addRDN(BCStyle.O, "ETFBL")
          .addRDN(BCStyle.CN, user.getUsername())
          .addRDN(BCStyle.EmailAddress, user.getEmail())
          .addRDN(BCStyle.TELEPHONE_NUMBER, user.getPhone());

      X500Name subjectUser = x500NameBuilder.build();
      X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(CACert.getSubject(),
          calculateSerialNumber(), calculateDate(0), calculateDate(ONE_MONTH_IN_HOURS * 6),
          subjectUser, userKey);
      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
      certBldr.addExtension(Extension.authorityKeyIdentifier,
              false, extUtils.createAuthorityKeyIdentifier(CACert))
          .addExtension(Extension.subjectKeyIdentifier,
              false, extUtils.createSubjectKeyIdentifier(userKey))
          .addExtension(Extension.keyUsage,
              true, new KeyUsage(
                  KeyUsage.digitalSignature));

      ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
          .build(CAKey);

      X509Certificate userCertificate = convertX509CertificateHolder(certBldr.build(signer));
      storeUserCertificate(userCertificate);

      return userCertificate;
    } catch (Exception e) {
      throw new Exception("Error while creating user certificate", e);
    }
  }

  private static void storeUserCertificate(X509Certificate userCertificate) throws IOException {
    File userCertificatesFolder = new File(USERS_CERTIFICATES_PATH);
    File userCertificateFile = new File(userCertificatesFolder,
        userCertificate.getSerialNumber() + ".crt");

    FileWriter fw = new FileWriter(userCertificateFile);
    JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
    pemWriter.writeObject(userCertificate);
    pemWriter.close();
    fw.close();
  }

  private static X509Certificate getUserCertificate(BigInteger certificateSerial)
      throws CertificateException, IOException {
    //dobavljanje sertifikata preko serijskog broja
    File userCertificatesFolder = new File(USERS_CERTIFICATES_PATH);
    File userCertificateFile = new File(userCertificatesFolder,
        certificateSerial.toString() + ".crt");

    try {
      FileInputStream fis = new FileInputStream(userCertificateFile);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
      fis.close();
      return certificate;
    } catch (FileNotFoundException e) {
      return null;
    }
  }

  public static X509Certificate getUserCertificate(String username) throws CertificateException {
    //dobavljanje sertifikata preko username
    File userCertificatesDirectory = new File(USERS_CERTIFICATES_PATH);

    try {
      File[] userCertificates = userCertificatesDirectory.listFiles();
      if (!Objects.isNull(userCertificates)) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (File cert : userCertificates) {
          FileInputStream fis = new FileInputStream(cert);
          //uzimamo username od sertifikata
          X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
          X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
          RDN cn = x500name.getRDNs(BCStyle.CN)[0];
          String commonName = IETFUtils.valueToString(cn.getFirst().getValue());
          //poredimo username sertifikata i unesenog username
          if (commonName.equals(username)) {
            return certificate;
          }
        }
        return null;
      }
      return null;
    } catch (FileNotFoundException e) {
      return null;
    }
  }

  public static X509Certificate getUserCertificateFromPKCS12(KeyStore keyStore) throws Exception {
    try {
      Enumeration<String> aliases = keyStore.aliases();
      String alias = aliases.nextElement();
      X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
      return cert;
    } catch (Exception e) {
      throw new Exception("Error while getting user's certificate from PKCS12.", e);
    }
  }

  public static void createUserPKCS12(User user) throws Exception {

    try {
      String password = "";
      do {
        System.out.println("Please enter your password again (used for PKCS12): ");
        password = SCANNER.nextLine();
      } while (!Password.validatePassword(user, password));

      Security.addProvider(new BouncyCastleProvider());
      KeyStore store = KeyStore.getInstance("PKCS12", "BC");
      store.load(null, null);
      store.setKeyEntry(user.getUsername(), user.getUserKeyPair().getPrivate(), null,
          new java.security.cert.Certificate[]{user.getUserCertificate()});

      FileOutputStream fout = new FileOutputStream(
          "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\PKCS12_Output\\"
              + user.getUsername() + ".p12"); //ovdje dobijamo pkcs12 koje koristi korisnik
      store.store(fout, password.toCharArray());

      fout.close();
    } catch (Exception e) {
      throw new Exception("Error while creating PKCS12 file.", e);
    }
  }

  public static KeyStore readPKCS12(String filePath, String password) throws Exception {

    try {
      Security.addProvider(new BouncyCastleProvider());
      KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
      FileInputStream fis = new FileInputStream(filePath);
      ks.load(fis, password.toCharArray());
      fis.close();
      return ks;
    } catch (Exception e) {
      throw new Exception("Error while reading PKCS12 file.", e);
    }
  }


  public static boolean certificateIsValid(X509Certificate cert) {

    try {
      X509Certificate CA = convertX509CertificateHolder(getCACertificate());
      if (Arrays.equals(cert.getIssuerUniqueID(), CA.getSubjectUniqueID())) {
        //verifikacija da je digitalni sertifikat izdat od strane CA kojem se vjeruje – provjera potpisa
        cert.verify(CA.getPublicKey());
        //verifikacija perioda validnosti
        cert.checkValidity();
        //provjera digital signature key usage
        boolean[] keyUsage = cert.getKeyUsage();
        if (!keyUsage[0]) {
          System.out.println("Digital signature key usage is not enabled!");
          return false;
        }
        return true;
      }
      return false;
    } catch (CertificateExpiredException e) {
      System.out.println("Certificate is expired.");
      return false;
    } catch (IOException | CertificateException e) {
      System.out.println("Certificate is not yet valid.");
      return false;
    } catch (GeneralSecurityException e) {
      System.out.println("Certificate is not signed by trusted CA.");
      return false;
    }
  }

  public static boolean crlExists() {
    File folder = new File(CRL_PATH);
    File file = new File(folder, "crl.crl");
    return file.exists();
  }

  public static X509CRLHolder getCRL() throws IOException {
    File folder = new File(CRL_PATH);
    File file = new File(folder, "crl.crl");

    FileInputStream fis = new FileInputStream(file);
    PEMParser pemParser = new PEMParser(new InputStreamReader(fis));
    X509CRLHolder crlHolder = (X509CRLHolder) pemParser.readObject();
    pemParser.close();
    fis.close();
    return crlHolder;
  }

  public static void writeCRL(X509CRLHolder crl, String crlName) throws IOException {
    File folder = new File(CRL_PATH);
    File file = new File(folder, crlName + ".crl");
    FileWriter fw = new FileWriter(file);
    JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
    pemWriter.writeObject(crl);
    pemWriter.close();
    fw.close();
  }

  public static void createCRL(X509Certificate certToRevoke)
      throws IOException, GeneralSecurityException, OperatorCreationException {
    PrivateKey caKey = RSAKey.getCAPrivateKey();
    X509CertificateHolder caCert = getCACertificate();

    X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(), calculateDate(0));
    crlGen.setNextUpdate(calculateDate(24 * 7));
    ExtensionsGenerator extGen = new ExtensionsGenerator();
    CRLReason crlReason = CRLReason.lookup(
        CRLReason.certificateHold); //razlog povlacenja sertifikata
    extGen.addExtension(Extension.reasonCode, false, crlReason);
    crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    crlGen.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(caCert));
    ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
        .build(caKey);

    writeCRL(crlGen.build(signer), "crl");
  }

  public static void updateCRL(X509CertificateHolder certToRevoke)
      throws IOException, GeneralSecurityException, OperatorCreationException {
    PrivateKey caKey = RSAKey.getCAPrivateKey();
    X509CertificateHolder caCert = getCACertificate();
    X509CRLHolder previousCRL = getCRL(); //postojeci crl

    X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getIssuer(), calculateDate(0));
    crlGen.setNextUpdate(calculateDate(24 * 7));
    ExtensionsGenerator extGen = new ExtensionsGenerator();
    CRLReason crlReason = CRLReason.lookup(
        CRLReason.certificateHold); //razlog povlacenja sertifikata
    extGen.addExtension(Extension.reasonCode, false, crlReason);
    crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());
    crlGen.addCRL(previousCRL); //dodaj na novi crl vec postojece sertifikate
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    crlGen.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(caCert));
    ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
        .build(caKey);

    writeCRL(crlGen.build(signer), "crl");
  }

  public static void removeFromCRL(X509CertificateHolder certificateToRemove)
      throws IOException, GeneralSecurityException, OperatorCreationException {

    X509CRLHolder crlHolder = getCRL();

    Security.addProvider(new BouncyCastleProvider());
    X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
    Set<X509CRLEntry> revokedCertificates = new HashSet<>(crl.getRevokedCertificates());

    int numberOfEntries = revokedCertificates.size(); //koliko ima sertifikata na CRL listi
    X509CRLEntry entryToRemove; //sertifikat koji se uklanja sa CRL liste
    boolean removed = false; //pomocni indetifikator koji govori da li je uklonjen sertifikat

    //lista sve sertifikate i pronalazi onaj koji treba da se ukloni
    for (X509CRLEntry entry : revokedCertificates) {
      if (entry.getSerialNumber().equals(certificateToRemove.getSerialNumber())) {
        entryToRemove = entry;
        revokedCertificates.remove(entryToRemove);
        numberOfEntries -= 1; //sada imamo jedan manje sertifikat
        removed = true; //indetifikujemo da smo uklonili jedan sertifikat sa liste
        break; //prekidamo listanje sertifikata
      }
    }
    //ako je uklonjen sertifikat, inace ne radimo nista
    if (removed) {
      X509Certificate firstCertificate;
      //cuvamo trenutnu CRL, prije uklanjanja sertifikata, kao staru CRL
      writeOldCRL(crlHolder);

      //ako nam je jedini sertifikat na CRL listi bio taj koji je uklonjen sada, pravimo praznu CRL listu
      if (numberOfEntries == 0) {
        if (revokedCertificates.isEmpty()) {
          createEmptyCRL();
        }
        //ako nam je ostao samo jedan sertifikat na CRL listi, pravimo novu sa tim jednim sertifikatom
      } else if (numberOfEntries == 1) {
        Iterator<X509CRLEntry> iterator = revokedCertificates.iterator();
        firstCertificate = getUserCertificate(iterator.next().getSerialNumber());
        createCRL(Objects.requireNonNull(firstCertificate));

        //ako imamo vise od 1 sertifikata na listi, potrebno je update listu
      } else {
        Iterator<X509CRLEntry> iterator = revokedCertificates.iterator();

        //uzimamo prvi sertifikat, pravimo novu CRL listu a nakon toga ostale dodajemo (update) na tu novu
        firstCertificate = getUserCertificate(iterator.next().getSerialNumber());
        createCRL(Objects.requireNonNull(firstCertificate));
        if (iterator.hasNext()) {
          for (X509CRLEntry entry : revokedCertificates) {
            //preskacemo prvi sertifikat jer se on vec nalazi na listi, pa samo radimo update i dodajemo ostale
            if (!entry.getSerialNumber().equals(firstCertificate.getSerialNumber())) {
              X509Certificate certificate = getUserCertificate(entry.getSerialNumber());
              updateCRL(Objects.requireNonNull(convertX509Certificate(certificate)));
            }
          }
        }
      }
    }
  }

  public static void createEmptyCRL()
      throws IOException, GeneralSecurityException, OperatorCreationException {
    X509CertificateHolder caCert = getCACertificate();
    PrivateKey caKey = getCAPrivateKey();

    X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(), calculateDate(0));
    crlGen.setNextUpdate(calculateDate(24 * 7));
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    crlGen.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(caCert));
    ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
        .build(caKey);

    writeCRL(crlGen.build(signer), "crl");
  }

  public static boolean isRevoked(X509Certificate certificate) throws IOException, CRLException {
    if (crlExists()) {
      X509CRLHolder crlHolder = getCRL();
      Security.addProvider(new BouncyCastleProvider());
      X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
      if (!Objects.isNull(crl.getRevokedCertificates())) {
        Set<X509CRLEntry> revokedCertificates = new HashSet<>(crl.getRevokedCertificates());
        for (X509CRLEntry entry : revokedCertificates) {
          if (entry.getSerialNumber().equals(certificate.getSerialNumber())) {
            return true;
          }
        }
      }
    }
    return false;
  }

  public static void writeOldCRL(X509CRLHolder crl) throws IOException {

    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy_HHmm");
    String formattedDateTime = now.format(formatter);
    FileWriter fw = new FileWriter(CRL_PATH + "OLD_" + formattedDateTime + ".crl");
    JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
    pemWriter.writeObject(crl);
    pemWriter.close();
    fw.close();
  }
}
