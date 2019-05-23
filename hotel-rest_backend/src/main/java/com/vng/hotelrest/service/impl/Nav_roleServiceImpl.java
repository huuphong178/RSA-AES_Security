package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.Nav_roleDAO;
import com.vng.hotelrest.entity.nav_role;
import com.vng.hotelrest.service.Nav_roleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class Nav_roleServiceImpl implements Nav_roleService {
    @Autowired
    Nav_roleDAO nav_roleDAO;

    @Override
    public List<nav_role> getAll() {
        return nav_roleDAO.findAll();
    }

    @Override
    public nav_role createAuth(nav_role nav) {
        return null;
    }

    @Override
    public void update(nav_role nav, String name) {
        nav_roleDAO.saveRole(name,nav.getRoles());
    }

    @Override
    public void delete(String username) {

    }
}
