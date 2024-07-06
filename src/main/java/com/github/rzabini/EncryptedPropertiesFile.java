package com.github.rzabini;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.util.Set;

public class EncryptedPropertiesFile {

    private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
    private static final String ENCRYPTED_VALUE_SUFFIX = ")";

    private final String masterPassword;
    private final Properties inMemoryProperties;

    public EncryptedPropertiesFile(String masterPassword, String propertyFile) {
        this.masterPassword = masterPassword;
        inMemoryProperties = encryptDecrypt(propertyFile);
    }

    public EncryptedPropertiesFile(Path masterPasswordFile, String propertyFile) {
        try {
            this.masterPassword = Files.readAllLines(masterPasswordFile, Charset.defaultCharset()).get(0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        inMemoryProperties = encryptDecrypt(propertyFile);
    }

    public Properties get(){
        return inMemoryProperties;
    }

    private Properties encryptDecrypt (String path) {
        try {
            return encryptDecrypt(path, ".*[pP]assword");
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }



    private Properties encryptDecrypt(String path, final String pattern) throws IOException {
        Properties inMemoryProps = new Properties();
        Properties onDiskProperties = new Properties();

        if(Files.exists(Paths.get(path))) {
            inMemoryProps.load(Files.newInputStream(Paths.get(path)));
            onDiskProperties.load(Files.newInputStream(Paths.get(path)));

            if (encryptOnDisk(pattern, onDiskProperties)) {
                onDiskProperties.store(Files.newOutputStream(Paths.get(path)), "");
            }

            decrypt(inMemoryProps);
        }
        return inMemoryProps;
    }

    private void decrypt(Properties inMemoryProps) {
        Set<String> keys = inMemoryProps.stringPropertyNames();
        keys.forEach(key -> {
            if (inMemoryProps.getProperty(key).startsWith(ENCRYPTED_VALUE_PREFIX)){
                inMemoryProps.setProperty(key, decryptText(inMemoryProps.getProperty(key)));
            }
        });
    }

    private boolean encryptOnDisk(String pattern, Properties onDiskProperties) {
        Set<String> keys = onDiskProperties.stringPropertyNames();
        final boolean[] needStore = {false};
        keys.forEach(key -> {
            if (key.matches(pattern) &&
                    !(onDiskProperties.getProperty(key).startsWith(ENCRYPTED_VALUE_PREFIX))){
                onDiskProperties.setProperty(key, String.format("%s%s%s", ENCRYPTED_VALUE_PREFIX,
                                encryptText(onDiskProperties.getProperty(key)), ENCRYPTED_VALUE_SUFFIX));
                        needStore[0] = true;
            }
        });
        return needStore[0];
    }

    private String encryptText(String value) {
        try{
            return AESUtil.encryptPasswordBased(masterPassword, value);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private String decryptText(String value) {
        try {
            return AESUtil.decryptPasswordBased(masterPassword, value.substring(
                    ENCRYPTED_VALUE_PREFIX.length(), value.length() - ENCRYPTED_VALUE_SUFFIX.length()));
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

}
