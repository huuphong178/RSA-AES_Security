package com.app.RSA;

import com.app.SHAHashing;
import com.app.callAPI.Helper;

import javax.crypto.Cipher;

import java.io.File;

import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DemoRSA {
    public static PrivateKey getPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(GenerateKeys.PRIVATE_KEY_FILE).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    public static PublicKey getPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(GenerateKeys.PUBLIC_KEY_FILE).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static String decryptedRSA(String dataEncrypted) throws Exception {
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] byteEncrypted=Base64.getDecoder().decode(dataEncrypted);
        byte[] byteDecrypted = cipher.doFinal(byteEncrypted);
        String decrypted = new String(byteDecrypted);
        return decrypted;
    }
    public static String enryptedSignature(String data) throws Exception {
        String original=SHAHashing.getSHAHash(data);
        System.out.println("SHA data: "+original);
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] byteEncrypted = cipher.doFinal(original.getBytes());
        String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
        return encrypted;
    }
    public static void main(String[] args) throws Exception {

        //System.out.println(getSecretKey())
//        String secret_Key= Helper.getSecretKeyFromServer();
//        String secretDecrypted=decryptedRSA(secret_Key);
//        GenerateKeys.writeToFile(GenerateKeys.SECRET_KEY_FILE,secretDecrypted.getBytes());
//
//        String temp=Helper.encryptAESData(Helper.POST_PARAMS);
//        String reponse=Helper.postRequest(temp);
//        System.out.println(Helper.decryptAESData(reponse));
        String original=SHAHashing.getSHAHash(Helper.POST_PARAMS);
        PrivateKey privateKey = getPrivateKey();
        PublicKey publicKey = getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] byteEncrypted = cipher.doFinal(original.getBytes());
        String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);


        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] byteDecrypted = cipher.doFinal(byteEncrypted);
        String decrypted = new String(byteDecrypted);
        System.out.println("original  text: " + original);
        System.out.println("encrypted text: " + encrypted);
        System.out.println("decrypted text: " + decrypted);
        if(original.equals(decrypted)==true){
            System.out.println("true");
        }


    }
}