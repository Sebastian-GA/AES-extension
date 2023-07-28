package com.sebastianga.aes;

import android.app.Activity;
import android.content.Context;
import com.google.appinventor.components.annotations.*;
import com.google.appinventor.components.runtime.*;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import android.util.Base64;

@DesignerComponent(version = 1, description = "Extension to encrypt string usin AES128 CBC mode with PKCS5Padding", category = ComponentCategory.EXTENSION, nonVisible = true, iconName = "")

@SimpleObject(external = true)
// Libraries
@UsesLibraries(libraries = "")
// Permissions
@UsesPermissions(permissionNames = "")

public class AESEncryption extends AndroidNonvisibleComponent {

    // Activity and Context
    private Context context;
    private Activity activity;

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CIPHER = "AES";
    private static final int AES_KEY_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 16;
    public static final int BASE64_FLAGS = Base64.NO_WRAP;

    public AESEncryption(ComponentContainer container) {
        super(container.$form());
        this.activity = container.$context();
        this.context = container.$context();
    }

    @SimpleFunction(description = "Encrypt string with SecretKey and IV formatted as UTF-8 string")
    public String AESEncryptUTF8(String plaintext, String secretKey, String iv) {
        return AES.encrypt(plaintext, AES.keyFromString(secretKey), AES.ivFromString(iv));
    }

    @SimpleFunction(description = "Encrypt string with SecretKey and IV formatted as HEX string")
    public String AESEncryptHEX(String plaintext, String secretKey, String iv) {
        return AES.encrypt(plaintext, AES.keyFromHexString(secretKey), AES.ivFromHexString(iv));
    }

    @SimpleFunction(description = "Decrypt string with SecretKey and IV formatted as UTF-8 string")
    public String AESDecryptUTF8(String ciphertext, String secretKey, String iv) {
        return AES.decrypt(ciphertext, AES.keyFromString(secretKey), AES.ivFromString(iv));
    }

    @SimpleFunction(description = "Decrypt string with SecretKey and IV formatted as HEX string")
    public String AESDecryptHEX(String ciphertext, String secretKey, String iv) {
        return AES.decrypt(ciphertext, AES.keyFromHexString(secretKey), AES.ivFromHexString(iv));
    }

    @SimpleFunction(description = "Generate random IV and return HEX string")
    public String generateIv() {
        return AES.ivHexString(AES.generateIv());
    }

    @SimpleFunction(description = "Generate random SecretKey and return HEX string")
    public String generateKey() throws NoSuchAlgorithmException {
        return AES.keyHexString(AES.generateKey());
    }

    public static final class AES {

        /*
         * -----------------------------------------------------------------
         * IV
         * -----------------------------------------------------------------
         */

        public static byte[] generateIv() {
            // fixPrng();
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);
            return iv;
        }

        public static byte[] ivFromString(String ivString) {
            byte[] iv = ivString.getBytes(StandardCharsets.UTF_8);
            if (iv.length != IV_LENGTH_BYTES) {
                throw new IllegalArgumentException(
                        "IV size is not " + IV_LENGTH_BYTES + " bytes, but " + iv.length + " bytes");
            }

            return iv;
        }

        public static byte[] ivFromHexString(String ivHexString) {
            int length = ivHexString.length();
            if (length / 2 != IV_LENGTH_BYTES) {
                throw new IllegalArgumentException(
                        "IV size is not " + IV_LENGTH_BYTES + " bytes, but " + length / 2 + " bytes");
            }

            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2) {
                String hex = ivHexString.substring(i, i + 2);
                byte value = (byte) Integer.parseInt(hex, 16);
                byteArray[i / 2] = value;
            }

            return byteArray;
        }

        public static String ivString(byte[] iv) {
            return new String(iv, StandardCharsets.UTF_8);
        }

        public static String ivHexString(byte[] iv) {
            StringBuilder hexBuilder = new StringBuilder();

            for (byte b : iv) {
                String hex = String.format("%02x", b);
                hexBuilder.append(hex);
            }

            return hexBuilder.toString();
        }

        /*
         * -----------------------------------------------------------------
         * KEY
         * -----------------------------------------------------------------
         */

        public static SecretKey generateKey() throws NoSuchAlgorithmException {
            // fixPrng();
            KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
            keyGen.init(AES_KEY_LENGTH_BITS);
            SecretKey secretKey = keyGen.generateKey();

            return secretKey;
        }

        public static SecretKey keyFromString(String keyString) {
            byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
            if (keyBytes.length != AES_KEY_LENGTH_BITS / 8) {
                throw new IllegalArgumentException(
                        "SecretKey size is not " + AES_KEY_LENGTH_BITS + " bits, but " + keyBytes.length * 8 + " bits");
            }

            return new SecretKeySpec(keyBytes, 0, keyBytes.length, CIPHER);
        }

        public static SecretKey keyFromHexString(String keyHexString) {
            int length = keyHexString.length();
            if (length / 2 != AES_KEY_LENGTH_BITS / 8) {
                throw new IllegalArgumentException(
                        "SecretKey size is not " + AES_KEY_LENGTH_BITS + " bytes, but " + length / 2 + " bytes");
            }

            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2) {
                String hex = keyHexString.substring(i, i + 2);
                byte value = (byte) Integer.parseInt(hex, 16);
                byteArray[i / 2] = value;
            }

            return new SecretKeySpec(byteArray, 0, byteArray.length, CIPHER);
        }

        public static String keyString(SecretKey secretKey) {
            // return new String(secretKey.getEncoded(), StandardCharsets.UTF_8);
            return "" + secretKey.getEncoded().length;
        }

        public static String keyHexString(SecretKey secretKey) {
            byte[] keyBytes = secretKey.getEncoded();
            StringBuilder hexBuilder = new StringBuilder();

            for (byte b : keyBytes) {
                String hex = String.format("%02x", b);
                hexBuilder.append(hex);
            }

            return hexBuilder.toString();
        }

        /*
         * -----------------------------------------------------------------
         * Encryption
         * -----------------------------------------------------------------
         */

        public static String encrypt(String plaintext, SecretKey secretKey, byte[] iv) {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

                iv = cipher.getIV(); // Some devices change the IV when encrypting?
                byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

                return Base64.encodeToString(ciphertext, BASE64_FLAGS); // Output is base64 encoded
            } catch (Exception e) {
                return "Error while encrypting: " + e.toString();
            }
        }

        /*
         * -----------------------------------------------------------------
         * Decryption
         * -----------------------------------------------------------------
         */

        public static String decrypt(String ciphertext, SecretKey secretKey, byte[] iv) {
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                byte[] plaintext = cipher.doFinal(Base64.decode(ciphertext, BASE64_FLAGS));

                return new String(plaintext, StandardCharsets.UTF_8);
            } catch (Exception e) {
                return "Error while decrypting: " + e.toString();
            }
        }

    }
}