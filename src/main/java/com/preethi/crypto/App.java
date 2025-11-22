package com.preethi.crypto;

import com.preethi.AES.AES;

public class App {
    public static void main(String[] args) {
        

        AES aes = new AES();
        String plainText = "Hello, this is a secret message!";
        try {
            // Encrypt the plaintext
            var cipherTextRecord = aes.encryptAES(plainText);
            System.out.println("Cipher Text: " + String.valueOf(cipherTextRecord));
            // Decrypt the ciphertext
            String decryptedText = aes.decryptAES(cipherTextRecord);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();    
        }
    
    }
}
