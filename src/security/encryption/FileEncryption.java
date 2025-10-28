package security.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class FileEncryption {

  private static final int MIN_SEGMENTS = 4;
  private static final int MAX_SEGMENTS = 9;
  private static final byte[] KEY_BYTES = Hex.decode("000102030405060708090a0b0c0d0e0f");
  private static final byte[] IV = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

  private static int numberOfSegments() {
    Random rand = new Random();
    return rand.nextInt((MAX_SEGMENTS - MIN_SEGMENTS) + 1) + MIN_SEGMENTS;
  }

  public static byte[] encryptFile(byte[] fileToEncrypt) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      SecretKeySpec key = new SecretKeySpec(KEY_BYTES, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
      byte[] output;
      output = cipher.doFinal(fileToEncrypt);
      return output;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public static byte[] decryptFile(byte[] fileToDecrypt) {

    try {
      Security.addProvider(new BouncyCastleProvider());
      SecretKeySpec key = new SecretKeySpec(KEY_BYTES, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
      byte[] finalOutput = new byte[cipher.getOutputSize(fileToDecrypt.length)];
      int len = cipher.update(fileToDecrypt, 0, fileToDecrypt.length, finalOutput, 0);
      len += cipher.doFinal(finalOutput, len);
      return Arrays.copyOfRange(finalOutput, 0, len);
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public static List<byte[]> splitFileToSegments(byte[] file) {

    int N = numberOfSegments();
    //System.out.println("segment: " + N);
    List<byte[]> segments = new ArrayList<>();

    if (file.length % N == 0) {
      int segment = file.length / N;
      for (int i = 0; i < file.length; i += segment) {
        byte[] tmpSegment = Arrays.copyOfRange(file, i, i + segment);
        segments.add(tmpSegment);
      }
      return segments;
    } else {
      int remainder = file.length % N;
      int segment = file.length / N;
      int j = 1; //pomocni brojac koji sluzi da se zadnjem segmentu doda visak
      byte[] tmpSegment;

      for (int i = 0; i < file.length; i += segment) {
        //kada dodjemo do zadnjeg segmenta potrebno je dodati visak bajtova
        if (j == N) {
          tmpSegment = Arrays.copyOfRange(file, i, i + segment + remainder);
          segments.add(tmpSegment);
          i += remainder;
        } else {
          tmpSegment = Arrays.copyOfRange(file, i, i + segment);
          segments.add(tmpSegment);
          j += 1;
        }
      }
      return segments;
    }
  }

  public static byte[] mergeFileSegments(List<byte[]> fileSegments) {

    int totalLength = 0;
    for (byte[] byteArray : fileSegments) {
      totalLength += byteArray.length;
    }
    byte[] file = new byte[totalLength];
    int currentLength = 0;
    for (byte[] byteArray : fileSegments) {
      System.arraycopy(byteArray, 0, file, currentLength, byteArray.length);
      currentLength += byteArray.length;
    }
    return file;
  }

  public static byte[] makeFileSignature(PrivateKey privateKey, byte[] fileToSign) {

    try {
      Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      signature.initSign(privateKey);
      signature.update(fileToSign);
      return signature.sign();
    } catch (Exception e) {
      //e.printStackTrace();
      return null;
    }
  }

  public static boolean verifyFileSignature(PublicKey publicKey, byte[] fileToVerify,
      byte[] signature) {

    try {
      Signature signatureVerifier = Signature.getInstance(SIGNATURE_ALGORITHM);
      signatureVerifier.initVerify(publicKey);
      signatureVerifier.update(fileToVerify);
      return signatureVerifier.verify(signature);
    } catch (Exception e) {
      //e.printStackTrace();
      return false;
    }
  }
}
