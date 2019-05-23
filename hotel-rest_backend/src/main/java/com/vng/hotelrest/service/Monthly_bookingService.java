package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.Monthly_booking;

import java.util.Date;
import java.util.List;

public interface Monthly_bookingService {
    List<Monthly_booking> getMonthly_bookingByDate(Date fromdate, Date todate, int top);
}
