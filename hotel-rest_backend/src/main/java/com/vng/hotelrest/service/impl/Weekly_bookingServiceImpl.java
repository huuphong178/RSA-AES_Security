package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.Weekly_bookingDAO;
import com.vng.hotelrest.entity.Weekly_booking;
import com.vng.hotelrest.service.Weekly_bookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

@Service
@Transactional
public class Weekly_bookingServiceImpl implements Weekly_bookingService {
    @Autowired
    Weekly_bookingDAO weekly_bookingDAO;
    @Override
    public List<Weekly_booking> getWeekly_bookingByDate(Date fromdate, Date todate, int top) {
        return weekly_bookingDAO.getWeekly_bookingByDate(fromdate, todate, top);
    }
}
