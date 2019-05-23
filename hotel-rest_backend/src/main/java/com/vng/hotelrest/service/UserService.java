package com.vng.hotelrest.service;


import com.vng.hotelrest.model.User;
import com.vng.hotelrest.model.UserDto;

import java.util.List;

public interface UserService {

    User save(UserDto user);
    List<User> findAll();
    void delete(long id);
    User findOne(String username);

    User findById(Long id);
}
