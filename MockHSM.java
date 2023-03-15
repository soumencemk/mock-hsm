import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MockHSM {

    private Map<String, Key> keyStore;
    
    public MockHSM() {
        keyStore = new HashMap<>();
    }
    
    public void generateRSAKeyPair(String keyName, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        keyStore.put(keyName + "_public", keyPair.getPublic());
        keyStore.put(keyName + "_private", keyPair.getPrivate());
    }
    
    public void generateAESKey(String keyName, int keySize) throws NoSuchAlgorithmException {
        byte[] keyBytes = new byte[keySize/8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);
        Key key = new SecretKeySpec(keyBytes, "AES");
        keyStore.put(keyName, key);
    }
    
    public byte[] encrypt(String keyName, byte[] plaintext) throws Exception {
        Key key = keyStore.get(keyName);
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
    
    public byte[] decrypt(String keyName, byte[] ciphertext) throws Exception {
        Key key = keyStore.get(keyName);
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }
    
    public static void main(String[] args) throws Exception {
        MockHSM hsm = new MockHSM();
        
        // Generate RSA key pair
        hsm.generateRSAKeyPair("my_rsa_key", 2048);
        
        // Generate AES key
        hsm.generateAESKey("my_aes_key", 256);
        
        // Encrypt plaintext using AES key
        byte[] plaintext = "Hello World!".getBytes();
        byte[] ciphertext = hsm.encrypt("my_aes_key", plaintext);
        System.out.println("Ciphertext: " + new String(ciphertext));
        
        // Decrypt ciphertext using AES key
        byte[] decryptedPlaintext = hsm.decrypt("my_aes_key", ciphertext);
        System.out.println("Decrypted plaintext: " + new String(decryptedPlaintext));
        
        // Encrypt plaintext using RSA public key
        byte[] rsaCiphertext = hsm.encrypt("my_rsa_key_public", plaintext);
        System.out.println("RSA ciphertext: " + new String(rsaCiphertext));
        
        // Decrypt ciphertext using RSA private key
        byte[] rsaDecryptedPlaintext = hsm.decrypt("my_rsa_key_private", rsaCiphertext);
        System.out.println("RSA decrypted plaintext: " + new String(rsaDecryptedPlaintext));
    }
}
