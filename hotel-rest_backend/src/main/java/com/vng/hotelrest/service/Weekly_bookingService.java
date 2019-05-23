package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.Weekly_booking;

import java.util.Date;
import java.util.List;

public interface Weekly_bookingService {
    List<Weekly_booking> getWeekly_bookingByDate(Date fromdate, Date todate, int top);
}
