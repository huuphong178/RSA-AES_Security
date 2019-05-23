package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.AuthDAO;
import com.vng.hotelrest.entity.Auth;
import com.vng.hotelrest.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class AuthServiceImpl implements AuthService {
    @Autowired
    AuthDAO authDAO;
    @Override
    public Auth login(String username, String password) {
        return authDAO.login(username, password);
    }

    @Override
    public List<Auth> getAll() {
        return authDAO.findAll();
    }

    @Override
    public Auth createAuth(Auth auth) {
        return authDAO.save(auth);
    }

    @Override
    public Auth getOne(String username) {

        return authDAO.getOne(username);
    }

    @Override
    public void update(Auth auth, String username) {
        authDAO.saveRole(auth.getRole(),username);
    }

    @Override
    public void delete(String username) {
        authDAO.deletebyUsername(username);
    }
}
