package com.app.callAPI;

import com.app.RSA.DemoRSA;
import com.app.RSA.GenerateKeys;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Helper {
        public static String host = "http://localhost:8080/";
        public static final String POST_PARAMS = "{\n" + "\"username\": \"admin\",\n" +
                "    \"password\": \"admin\"" + "\n}";
        public static String getSecretKeyFromServer()throws Exception{
                URL urlForGetRequest = new URL(host+"rsa/secret_key");
                String secretKey="";
                String readLine = null;
                HttpURLConnection conection = (HttpURLConnection) urlForGetRequest.openConnection();
                conection.setRequestMethod("GET");
                int responseCode = conection.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                        BufferedReader in = new BufferedReader(
                                new InputStreamReader(conection.getInputStream()));
                        StringBuffer response = new StringBuffer();
                        while ((readLine = in .readLine()) != null) {
                                response.append(readLine);
                        } in .close();
                        // print result
                        // System.out.println("JSON String Result " + response.toString());
                        JSONObject jsonObj = new JSONObject(response.toString());
                        secretKey= (String) jsonObj.get("secretKey");
                }
                return secretKey;

        }
        public static String postRequest(String data, String header) throws Exception {
                URL obj = new URL(host+"rsa/data2");
                HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
                postConnection.setRequestMethod("POST");
                postConnection.setRequestProperty ("Authorization", header);
                postConnection.setRequestProperty("Content-Type", "application/json");
                postConnection.setDoOutput(true);
                OutputStream os = postConnection.getOutputStream();
                os.write(data.getBytes());
                os.flush();
                os.close();
                int responseCode = postConnection.getResponseCode();
                System.out.println("POST Response Code :  " + responseCode);
                System.out.println("POST Response Message : " + postConnection.getResponseMessage());
                if (responseCode == HttpURLConnection.HTTP_OK) { //success
                        BufferedReader in = new BufferedReader(new InputStreamReader(
                                postConnection.getInputStream()));
                        String inputLine;
                        StringBuffer response = new StringBuffer();
                        while ((inputLine = in .readLine()) != null) {
                                response.append(inputLine);
                        } in .close();
                        // print result
                        System.out.println(response.toString());
                        return response.toString();
                        //System.out.println(decryptAESData(response.toString()));
                } else {
                       // System.out.println("POST NOT WORKED");
                }
                return "";
        }
        public static String decryptAESData(String dataEncrypted) throws Exception {
                JSONObject jsonObj = new JSONObject(dataEncrypted);
                String jsonData= (String) jsonObj.get("dataEncrypted");
                SecretKeySpec skeySpec = new SecretKeySpec(GenerateKeys.getSecretKey().getBytes(), "AES");
                Cipher cipher = null;
                cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                byte[] byteEncrypted= Base64.getDecoder().decode(jsonData);
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
                byte[] byteDecrypted = cipher.doFinal(byteEncrypted);
                String decrypted = new String(byteDecrypted);
                return decrypted;
        }
        public static String encryptAESData(String data) throws Exception {
                SecretKeySpec skeySpec = new SecretKeySpec(GenerateKeys.getSecretKey().getBytes(), "AES");
                Cipher cipher = null;
                cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                byte[] byteEncrypted = cipher.doFinal(data.getBytes());
                String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
                return "{\"dataEncrypted\": \""+encrypted+"\"}";

        }
}
