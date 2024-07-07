package com.github.rzabini;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Set;

/**
 * Encrypts with a master password the password entries contained in a properties file at the first access to the file.
 * On successive accesses reads the properties file and decrypts password entries.
 */
public final class EncryptedProperties {

    private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
    private static final String ENCRYPTED_VALUE_SUFFIX = ")";

    private EncryptedProperties() {

    }

    public static Properties create(final String masterPassword, final Path propertyFile)
            throws IOException {
        return encryptDecrypt(propertyFile, masterPassword);
    }

    private static Properties encryptDecrypt(final Path path, final String masterPassword) throws IOException {
        return encryptDecrypt(path, ".*[pP]assword", masterPassword);
    }
    private static Properties encryptDecrypt(final Path path, final String pattern, final String masterPassword)
            throws IOException {
        final Properties inMemoryProps = new Properties();
        final Properties onDiskProperties = new Properties();


        if (Files.exists(path)) {
            try (InputStream inStream = Files.newInputStream(path)) {
                inMemoryProps.load(inStream);
            }
            try (InputStream inStream = Files.newInputStream(path)) {
                onDiskProperties.load(inStream);
            }

            if (encryptOnDisk(pattern, onDiskProperties, masterPassword)) {
                try (OutputStream outputStream = Files.newOutputStream(path)) {
                    onDiskProperties.store(outputStream, "");
                }
            }
            decrypt(inMemoryProps, masterPassword);
        }
        return inMemoryProps;
    }

    private static void decrypt(final Properties inMemoryProps, final String masterPassword) {
        final Set<String> keys = inMemoryProps.stringPropertyNames();
        keys.forEach(key -> {
            if (inMemoryProps.getProperty(key).startsWith(ENCRYPTED_VALUE_PREFIX)) {
                inMemoryProps.setProperty(key, decryptText(inMemoryProps.getProperty(key), masterPassword));
            }
        });
    }

    private static boolean encryptOnDisk(final String pattern, final Properties onDiskProperties,
                                         final String masterPassword) {
        final Set<String> keys = onDiskProperties.stringPropertyNames();
        final boolean[] needStore = {false};
        keys.forEach(key -> {
            if (key.matches(pattern)
                    && !(onDiskProperties.getProperty(key).startsWith(ENCRYPTED_VALUE_PREFIX))) {
                onDiskProperties.setProperty(key, String.format("%s%s%s", ENCRYPTED_VALUE_PREFIX,
                                encryptText(onDiskProperties.getProperty(key), masterPassword),
                        ENCRYPTED_VALUE_SUFFIX));
                        needStore[0] = true;
            }
        });
        return needStore[0];
    }

    private static String encryptText(final String value, final String masterPassword) {
        try {
            return AESUtil.encryptPasswordBased(masterPassword, value);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String decryptText(final String value, final String masterPassword) {
        try {
            return AESUtil.decryptPasswordBased(masterPassword, value.substring(
                    ENCRYPTED_VALUE_PREFIX.length(), value.length() - ENCRYPTED_VALUE_SUFFIX.length()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
