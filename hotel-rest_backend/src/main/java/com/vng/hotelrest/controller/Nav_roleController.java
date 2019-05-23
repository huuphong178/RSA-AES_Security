package com.vng.hotelrest.controller;


import com.google.gson.Gson;
import com.vng.hotelrest.entity.Auth;
import com.vng.hotelrest.entity.nav_role;
import com.vng.hotelrest.service.AuthService;
import com.vng.hotelrest.service.Nav_roleService;
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
public class Nav_roleController {
    @Autowired
    private Gson gson;
    @Autowired
    private Nav_roleService nav_roleService;
    @RequestMapping(value = "/nav_role", method = RequestMethod.GET, produces = "application/json")
    public String getAll() {
        List<nav_role> navList =new ArrayList<>();
        try {
            navList =  nav_roleService.getAll();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(navList);
    }
    @PostMapping(value="/createNavRole",headers="Accept=application/json")
    public ResponseEntity<nav_role> createNavRole(@RequestBody nav_role auth, UriComponentsBuilder ucBuilder){
       // nav_role nav_roleret =nav_roleService.createAuth(auth);
       // if (nav_roleret==null) {
            return new ResponseEntity<nav_role>(HttpStatus.BAD_REQUEST);
       // }
       // return new ResponseEntity<nav_role> (nav_roleret, HttpStatus.OK);
    }
    @PutMapping(value="/nav_role", headers="Accept=application/json")
    public ResponseEntity<nav_role> updateNavRole(@RequestBody nav_role authreq)
    {
        //nav_role auth = nav_roleService.update(authreq.getUsername());
        //if (auth==null) {
        //    return new ResponseEntity<nav_role>(HttpStatus.NOT_FOUND);
        //}
        nav_roleService.update(authreq, authreq.getName());
        return new ResponseEntity<nav_role>(HttpStatus.OK);
    }
    @DeleteMapping(value="/nav_role/{id}", headers ="Accept=application/json")
    public ResponseEntity<nav_role> deleteAuth(@PathVariable("id") String id){
       // nav_role auth = nav_roleService.getOne(id);
       // if (auth == null) {
            return new ResponseEntity<nav_role>(HttpStatus.NOT_FOUND);
       // }
       // authService.delete(id);
      //  return new ResponseEntity<nav_role>(HttpStatus.OK);
    }
}
