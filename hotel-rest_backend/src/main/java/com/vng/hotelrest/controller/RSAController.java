package com.vng.hotelrest.controller;

import com.vng.hotelrest.entity.Auth;
import com.vng.hotelrest.model.objectAES;
import com.vng.hotelrest.service.AuthService;
import com.vng.hotelrest.until.Helper;
import javassist.NotFoundException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


@CrossOrigin()
@RestController
@RequestMapping("/rsa")
@Controller
public class RSAController {
    @Autowired
    private AuthService authService;


    @GetMapping(value="/secret_key",headers="Accept=application/json")
    public String WriteSecretKey() throws Exception {

        String secretKey=Helper.randomAlphaNumeric(32);
        String result=Helper.encryptedRSASecret(secretKey);
        System.out.println(secretKey);
        Helper.writeToFile(Helper.SECRET_KEY_FILE, secretKey.getBytes());
        return "{\"secretKey\": \""+result+"\"}";
    }

    @PostMapping(value="/data",headers="Accept=application/json")
    public String signIn(@RequestHeader String Authorization, @RequestBody Auth auth, UriComponentsBuilder ucBuilder) throws Exception {
        System.out.println(Authorization);
        Auth ret =authService.login(auth.getUsername(), auth.getPassword());
        if (ret==null) {
            return Helper.encryptAESData("{\"status\": \"false\"}");
            //return "{\"status\": \"false\"}";
        }
        //return "{\"status\": \"true\",\"role\":\""+ret.getRole()+"\",\"username\":\""+ret.getUsername()+"\"}";
        return Helper.encryptAESData("{\"status\": \"true\",\"role\":\""+ret.getRole()+"\",\"username\":\""+ret.getUsername()+"\"}");
    }

    @RequestMapping(value = "/data2", method = RequestMethod.POST,headers="Accept=application/json")
    public String postsRequest(@RequestHeader String Authorization, @RequestBody objectAES dataEncrypted) throws Exception {
        System.out.println("Header: "+ Authorization);
        System.out.println("Request: "+dataEncrypted.getDataEncrypted());
        //Giai ma data nhan duoc
        String decrypted=Helper.decryptAESData(dataEncrypted.getDataEncrypted());
        System.out.println("Giai ma: "+decrypted);
        //Kiem tra tinh toan ven du lieu va dung nguoi gui hay khong
        Boolean checkSignature=Helper.CheckSignature(decrypted,Authorization);
        System.out.println("Ket qua check Singnature: "+ checkSignature);
        if(!checkSignature){
            return null;
        }
        //Xu ly du lieu nhan duoc
        JSONObject jsonObj = new JSONObject(decrypted);
        Auth ret =authService.login(jsonObj.getString("username"), jsonObj.getString("password"));
        if (ret==null) {
            return Helper.encryptAESData("{\"status\": \"false\"}");
           // return "{\"status\": \"false\"}";
        }
       // return "{\"status\": \"true\",\"role\":\""+ret.getRole()+"\",\"username\":\""+ret.getUsername()+"\"}";
        return Helper.encryptAESData("{\"status\": \"true\",\"role\":\""+ret.getRole()+"\",\"username\":\""+ret.getUsername()+"\"}");
    }
}
