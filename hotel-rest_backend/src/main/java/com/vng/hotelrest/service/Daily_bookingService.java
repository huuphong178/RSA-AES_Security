package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.Daily_booking;

import javax.xml.crypto.Data;
import java.util.Date;
import java.util.List;

public interface Daily_bookingService {
    List<Daily_booking> getDaily_bookingByDate(Date fromdate, Date todate, int top);
}
