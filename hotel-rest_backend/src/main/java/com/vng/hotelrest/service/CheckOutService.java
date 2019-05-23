package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.CheckOut;

import java.util.List;

public interface CheckOutService {
    List<CheckOut> getAll();
    List<Integer> getchartHotelTotal();
}
