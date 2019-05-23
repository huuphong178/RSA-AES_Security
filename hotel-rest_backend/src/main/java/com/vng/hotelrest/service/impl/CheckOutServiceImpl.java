package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.CheckOutDAO;
import com.vng.hotelrest.entity.CheckOut;
import com.vng.hotelrest.service.CheckOutService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Service
@Transactional
public class CheckOutServiceImpl implements CheckOutService {
    @Autowired
    CheckOutDAO checkOutDAO;
    @Override
    public List<CheckOut> getAll() {
        return checkOutDAO.findAll();
    }
    @Override
    public List<Integer> getchartHotelTotal(){
        List<Integer> ret = new ArrayList<>();
        ret.add(0);ret.add(0);ret.add(0);ret.add(0);
        ret.add(0);ret.add(0);ret.add(0);ret.add(0);
        ret.add(0);ret.add(0);ret.add(0);ret.add(0);
        List<CheckOut> checkouts=this.getAll();
        for (CheckOut checkout: checkouts
             ) {
            Date datebooking=checkout.getCheckOutDate();
            Long totalamount=(Long)checkout.getTotalAmount();
            Calendar cal = Calendar.getInstance();
            cal.setTime(datebooking);
            int month = cal.get(Calendar.MONTH);
            ret.set(month, (int) (ret.get(month)+totalamount));
        }
        return ret;
    }
}
