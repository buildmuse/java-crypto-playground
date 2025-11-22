package com.preethi.AES;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

record cipherText(String text, SecretKey key){}

public class AES {
    private final int IV_LENGTH_BYTES = 12;
    private final int TAG_LENGTH_BITS = 128;
    private final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding"; 

    private SecretKey getKey() throws java.security.NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] IV = new byte[IV_LENGTH_BYTES];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(IV);

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] cipherTextWithIV = new byte[IV.length + cipherText.length];
        System.arraycopy(IV, 0, cipherTextWithIV, 0, IV.length);
        System.arraycopy(cipherText, 0, cipherTextWithIV, IV.length, cipherText.length);

         return Base64.getEncoder().encodeToString(cipherTextWithIV);
    }

    private String decrypt(String input, SecretKey key) throws Exception {

        byte[] cipherTextWithIV = Base64.getDecoder().decode(input);

        byte[] IV = new byte[IV_LENGTH_BYTES];
        byte[] cipherText = new byte[cipherTextWithIV.length - IV_LENGTH_BYTES];

        System.arraycopy(cipherTextWithIV, 0, IV, 0, IV_LENGTH_BYTES);
        System.arraycopy(cipherTextWithIV, IV_LENGTH_BYTES, cipherText, 0, cipherText.length);

        
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, IV);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, java.nio.charset.StandardCharsets.UTF_8);
    }

    public cipherText encryptAES(String input) throws Exception {
        SecretKey key = getKey();
        String cipherText = encrypt(input, key);
        return new cipherText(cipherText, key);
    }

    public String decryptAES(cipherText input) throws Exception {
        return decrypt(input.text(), input.key());
    }

}
