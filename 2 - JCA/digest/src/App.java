import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class App {

    public static void main(String[] args) throws Exception {
        Integer messageNumber = 30;
        String algorithm = "SHA-256";
        SecretKey privateKey = generateSecretKey();
        Double probability = 0.2;

        for (int i = 0; i < messageNumber; i++)
        {
            String message = "MSG: " + i;
            String cipherText = encrypt(message, privateKey);
            byte[] digestSentData = digest(cipherText, algorithm);

            System.out.println("Invio del messaggio: " + message);

            cipherText = communication(cipherText, probability);

            byte[] digestReceivedData = digest(cipherText, algorithm);

            if (Arrays.equals(digestSentData, digestReceivedData))
                System.out.println("Messaggio ricevuto correttamente: " + decrypt(cipherText, privateKey));
            else
                System.out.println("Messaggio corrotto");

            System.out.println("____________________________________________________________________________________");
        }
    }

    private static byte[] digest(String inputString, String algorithm)
    {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return digest.digest(inputString.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey generateSecretKey() throws Exception {
        // Genera una chiave segreta AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Lunghezza della chiave, può essere 128, 192 o 256 bit
        return keyGenerator.generateKey();
    }

    private static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        // Ottiene un oggetto Cipher per l'operazione di cifratura con AES
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Cifra il messaggio
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Codifica il risultato in Base64 per una rappresentazione sicura
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        // Ottiene un oggetto Cipher per l'operazione di decifratura con AES
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decifra il messaggio
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        // Converte il risultato in stringa
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static String communication(String message, Double probability)
    {
        if (new Random().nextDouble() <= probability)
            return new StringBuilder(message).reverse().toString();
        else
            return message;
    }

}
