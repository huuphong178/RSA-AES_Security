package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.Monthly_bookingDAO;
import com.vng.hotelrest.entity.Monthly_booking;
import com.vng.hotelrest.service.Monthly_bookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

@Service
@Transactional
public class Monthly_bookingServiceImpl implements Monthly_bookingService {
    @Autowired
    Monthly_bookingDAO monthly_bookingDAO;
    @Override
    public List<Monthly_booking> getMonthly_bookingByDate(Date fromdate, Date todate, int top) {
        return monthly_bookingDAO.getMonthly_bookingByDate(fromdate, todate, top);
    }
}
