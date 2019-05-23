package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.nav_role;

import java.util.List;

public interface Nav_roleService {
    List<nav_role> getAll();
    nav_role createAuth(nav_role nav);
    void update(nav_role nav, String name);
    void delete(String username);
}
