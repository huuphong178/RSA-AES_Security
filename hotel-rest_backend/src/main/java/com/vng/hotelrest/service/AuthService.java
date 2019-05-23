package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.Auth;

import java.util.List;

public interface AuthService {
    Auth login(String username, String password);
    List<Auth> getAll();
    Auth createAuth(Auth room);
    Auth getOne(String username);
    void update(Auth auth, String username);
    void delete(String username);
}
