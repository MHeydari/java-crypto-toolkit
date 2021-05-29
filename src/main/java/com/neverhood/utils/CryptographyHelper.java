package  com.neverhood.utils;

import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class CryptographyHelper {
    public static byte[] encodeToBase64(byte[] clearData) {
        return Base64Utils.encode(clearData);
    }

    public static byte[] decodeFromBase64(byte[] encodedData) {
        return Base64Utils.decode(encodedData);
    }

    public static String encodeToBas64(String cleartext) {
            return Base64Utils.encodeToString(cleartext.getBytes(StandardCharsets.UTF_8));
    }
    public static String decodeFromBas64(String encryptedText) {
        return new String(Base64Utils.decodeFromString(encryptedText), StandardCharsets.UTF_8);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
        return instance.generateKeyPair();
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey)
            throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(data);

        return sig.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] data,
                                 byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }

    public static String createSignature(String privateKeyString, String data)
            throws Exception {
        byte[] private_bytes = decodeFromBase64(privateKeyString.getBytes());
        PrivateKey privateKey = retrievePrivateKeyFromEncoded(private_bytes);

        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] sign = sign(bytes, privateKey);
        byte[] sign_64 = encodeToBase64(sign);

        return new String(sign_64);
    }

    public static String createSignature(PrivateKey privateKey, String data)
            throws Exception {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] sign = sign(bytes, privateKey);
        byte[] sign_64 = encodeToBase64(sign);

        return new String(sign_64);
    }

    public static byte[] encrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.PUBLIC_KEY, key);
        ByteArrayOutputStream dest = new ByteArrayOutputStream();
        CipherOutputStream out = new CipherOutputStream(dest, cipher);
        out.write(data);
        out.close();
        return dest.toByteArray();
    }

    public static byte[] decrypt(byte[] encoded, Key key) throws Exception {
        //TODO:
        /*boolean isUnlimitedCryptographyEnabled = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
        if (!isUnlimitedCryptographyEnabled){}
        else{}*/

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encoded);
    }

    public static byte[] getModulusOfPublicKey(PublicKey publicKey) {
        return ((RSAPublicKey) publicKey).getModulus().toByteArray();
    }

    public static PublicKey retrievePublicKeyFromModulus(byte[] modulus)
            throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(1, modulus),
                        new BigInteger("65537")));
    }

    public static PrivateKey retrievePrivateKeyFromEncoded(byte[] encodedKey)
            throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(encodedKey));
    }



}
