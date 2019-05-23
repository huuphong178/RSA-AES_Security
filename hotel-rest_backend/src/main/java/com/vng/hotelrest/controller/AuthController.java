package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.Auth;
import com.vng.hotelrest.service.AuthService;
import com.vng.hotelrest.service.BookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class AuthController {
    @Autowired
    private Gson gson;
    @Autowired
    private AuthService authService;
    @PostMapping(value="/auth",headers="Accept=application/json")
    public String signIn(@RequestBody Auth auth, UriComponentsBuilder ucBuilder){
        Auth ret =authService.login(auth.getUsername(), auth.getPassword());
        if (ret==null) {
            return "{\"status\": \"false\"}";
        }

        return "{\"status\": \"true\",\"role\":\""+ret.getRole()+"\",\"username\":\""+ret.getUsername()+"\"}";
    }
    @RequestMapping(value = "/auth", method = RequestMethod.GET, produces = "application/json")
    public String getAll() {
        List<Auth> authList =new ArrayList<>();
        try {
            authList =  authService.getAll();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(authList);
    }
    @GetMapping(value = "/auth/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Auth> getOne(@PathVariable("id") String id) {
        System.out.println("Fetching User with id " + id);
        Auth auth = authService.getOne(id);
        auth.setPassword("");
        if (auth == null) {
            return new ResponseEntity<Auth>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<Auth>(auth, HttpStatus.OK);
    }

    @PostMapping(value="/createAuth",headers="Accept=application/json")
    public ResponseEntity<Auth> createAuth(@RequestBody Auth auth, UriComponentsBuilder ucBuilder){
        Auth authret =authService.createAuth(auth);
        if (authret==null) {
            return new ResponseEntity<Auth>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<Auth> (authret, HttpStatus.OK);
    }
    @PutMapping(value="/auth", headers="Accept=application/json")
    public ResponseEntity<Auth> updateAuth(@RequestBody Auth authreq)
    {
        Auth auth = authService.getOne(authreq.getUsername());
        if (auth==null) {
            return new ResponseEntity<Auth>(HttpStatus.NOT_FOUND);
        }
        authService.update(authreq, authreq.getUsername());
        return new ResponseEntity<Auth>(HttpStatus.OK);
    }
    @DeleteMapping(value="/auth/{id}", headers ="Accept=application/json")
    public ResponseEntity<Auth> deleteAuth(@PathVariable("id") String id){
        Auth auth = authService.getOne(id);
        if (auth == null) {
            return new ResponseEntity<Auth>(HttpStatus.NOT_FOUND);
        }
        authService.delete(id);
        return new ResponseEntity<Auth>(HttpStatus.OK);
    }

}
