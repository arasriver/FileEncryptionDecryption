import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class FileEncryptionDecryption {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final String KEY = "mysecretpassword";

    public static void encrypt(String inputFile, String outputFile) throws Exception {
        Key secretKey = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        byte[] outputBytes = cipher.doFinal(inputBytes);

        Files.write(Paths.get(outputFile), Base64.getEncoder().encode(outputBytes));
    }

    public static void decrypt(String inputFile, String outputFile) throws Exception {
        Key secretKey = new SecretKeySpec(KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] inputBytes = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(inputFile)));
        byte[] outputBytes = cipher.doFinal(inputBytes);

        Files.write(Paths.get(outputFile), outputBytes);
    }

    public static void main(String[] args) {
        try {
            // Encrypt the file
            encrypt("input.txt", "encrypted.txt");
            System.out.println("File encrypted successfully.");

            // Decrypt the file
            decrypt("encrypted.txt", "decrypted.txt");
            System.out.println("File decrypted successfully.");
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
}
