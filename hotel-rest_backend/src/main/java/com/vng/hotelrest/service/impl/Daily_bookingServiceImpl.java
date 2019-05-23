package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.Daily_bookingDAO;
import com.vng.hotelrest.entity.Daily_booking;
import com.vng.hotelrest.service.Daily_bookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
@Service
@Transactional
public class Daily_bookingServiceImpl implements Daily_bookingService {
    @Autowired
    Daily_bookingDAO daily_bookingDAO;
    @Override
    public List<Daily_booking> getDaily_bookingByDate(Date fromdate, Date todate, int top) {
        return daily_bookingDAO.getDaily_bookings(fromdate, todate, top);
    }
}
