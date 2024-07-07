package com.github.rzabini;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

final class AESUtil {

    private static final String SALT = "123454321";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private AESUtil() { }

    public static SecretKey getKeyFromPassword(final String password, final String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65_536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] randomBytes() {
        final byte[] iv = new byte[16];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    private static IvParameterSpec generateIv(byte[] iv) {
        return new IvParameterSpec(iv);
    }

    private static String encryptPasswordBased(final String plainText, final SecretKey key, final byte[] iv)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, generateIv(iv));
        final byte[] ciphertext = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        // Prepend IV to the ciphertext (or handle it as needed)
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    static String encryptPasswordBased(final String masterPassword, final String value)
            throws GeneralSecurityException {
        return encryptPasswordBased(value, getKeyFromPassword(masterPassword, SALT), randomBytes());
    }
    private static String decryptPasswordBased(final byte[] combined, final SecretKey key)
            throws GeneralSecurityException {
        // Extract the IV
        byte[] iv = new byte[16];
        System.arraycopy(combined, 0, iv, 0, iv.length);

        // Extract the ciphertext
        byte[] ciphertext = new byte[combined.length - iv.length];
        System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, generateIv(iv));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }
    static String decryptPasswordBased(final String masterPassword, final String encryptedData)
            throws GeneralSecurityException {
        byte[] combined = Base64.getDecoder().decode(encryptedData);
        return decryptPasswordBased(combined, getKeyFromPassword(masterPassword, SALT));
    }
}
