package com.vng.hotelrest.service;


import com.vng.hotelrest.entity.Booking;

import java.util.List;

public interface BookingService {
    List<Booking> getAll();
    List<Integer> getRoomTypeChartAll();
    List<Integer> getRoomTypeChart(int month, int year);
    List<Integer> getRoomTypeChart(int year);
    List<Integer> getRoomTypeChartTri(int trimester, int year);
    Long getCountBooking(int month, int year);
    Long getCountBooking(int year);
    Long getCountBookingTri(int trimester, int year);
    Long getCountBooking();
}
