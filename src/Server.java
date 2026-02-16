import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Server {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started, listening on port: " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                    DataInputStream din = new DataInputStream(clientSocket.getInputStream());
                    DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream())) {

                    // Passing userid, aeskey and signature to server
                    int useridLength = din.readInt();
                    byte[] useridBytes = new byte[useridLength];
                    din.readFully(useridBytes);
                    String userid = new String(useridBytes);

                    int aeskeyLength = din.readInt();
                    byte[] aeskeyBytes = new byte[aeskeyLength];
                    din.readFully(aeskeyBytes);

                    int signatureLength = din.readInt();
                    byte[] signatureBytes = new byte[signatureLength];
                    din.readFully(signatureBytes);

                    System.out.println("User " + userid + " connected.");

                    // Verifying signature
                    try (FileInputStream clientPubKeyFile = new FileInputStream(userid + ".pub")) {
                        byte[] clientPubKeyBytes = clientPubKeyFile.readAllBytes();
                        PublicKey clientPubKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));

                        Signature rsaSignature = Signature.getInstance("SHA256withRSA");
                        rsaSignature.initVerify(clientPubKey);

                        rsaSignature.update(useridBytes);
                        rsaSignature.update(aeskeyBytes);

                        boolean isValid = rsaSignature.verify(signatureBytes);

                        if (isValid) {
                            dout.writeBoolean(true);
                            // If valid, use the master private key to decrypt
                            try (FileInputStream masterPrivKeyFile = new FileInputStream("server-b64.prv")) {
                                byte[] masterPrivKeyContents = masterPrivKeyFile.readAllBytes();
                                byte[] masterPrivKeyBytes = Base64.getMimeDecoder().decode(masterPrivKeyContents);
                                PrivateKey masterPrivKey = kf.generatePrivate(new PKCS8EncodedKeySpec(masterPrivKeyBytes));

                                Cipher masterCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                masterCipher.init(Cipher.DECRYPT_MODE, masterPrivKey);

                                byte[] decryptedAesBytes = masterCipher.doFinal(aeskeyBytes);

                                dout.writeInt(decryptedAesBytes.length);
                                dout.write(decryptedAesBytes);

                                System.out.println("Signature verified. Key decrypted and sent.");
                            }
                        } else {
                            dout.writeBoolean(false);
                            System.out.println("Signature not verified.");
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Client error: " + e.getMessage());
                }
            }
        }
    }
}
