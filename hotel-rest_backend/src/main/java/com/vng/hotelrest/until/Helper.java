package com.vng.hotelrest.until;

import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Helper {
    public static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    public static final String SECRET_KEY_FILE = "rsa_keypair/secretKey";
    public static final String PUBLIC_KEY_FILE = "rsa_keypair/publicKey";
    public static PublicKey getPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
    public static String getSecretKey() throws IOException {
        byte[] keyBytes = Files.readAllBytes(new File(SECRET_KEY_FILE).toPath());
        String keyString = new String(keyBytes);
        return keyString;
    }
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }
    public static String encryptedRSASecret(String secretKey) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] byteEncrypted = cipher.doFinal(secretKey.getBytes());
        String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
        return encrypted;
    }
    public static String decryptAESData(String dataEncrypted) throws Exception {
        System.out.println(dataEncrypted);
        SecretKeySpec skeySpec = new SecretKeySpec(getSecretKey().getBytes(), "AES");
        Cipher cipher = null;
        cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        byte[] byteEncrypted= Base64.getDecoder().decode(dataEncrypted);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] byteDecrypted = cipher.doFinal(byteEncrypted);
        String decrypted = new String(byteDecrypted);
        return decrypted;
    }
    public static String encryptAESData(String data) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(getSecretKey().getBytes(), "AES");
        Cipher cipher = null;
        cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] byteEncrypted = cipher.doFinal(data.getBytes());
        String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
        return "{\"dataEncrypted\": \""+encrypted+"\"}";

    }
    public static String deryptedSignature(String signature) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] byteEncrypted= Base64.getDecoder().decode(signature);
        byte[] byteDecrypted = cipher.doFinal(byteEncrypted);
        String decrypted = new String(byteDecrypted);
        return decrypted;
    }
    public static boolean CheckSignature(String data, String header) throws Exception {
        String shaData=SHAHashing.getSHAHash(data);
        System.out.println("sshdata:"+shaData);
        String shaHeader=deryptedSignature(header);
        System.out.println("sshHeader:"+shaHeader);
        if(shaData.equals(shaHeader)==true){
            return true;
        }
        return false;
    }
}
