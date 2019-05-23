package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.Monthly_booking;
import com.vng.hotelrest.entity.Weekly_booking;
import com.vng.hotelrest.service.Monthly_bookingService;
import com.vng.hotelrest.service.Weekly_bookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class Monthly_bookingController {
    @Autowired
    private Gson gson;
    @Autowired
    private Monthly_bookingService monthly_bookingService;
    @GetMapping(value = "/getMonthly_booking", produces = MediaType.APPLICATION_JSON_VALUE,params = {"fromdate","todate","top"})
    @ResponseBody
    public String getMonthly_bookingByDate(@RequestParam("fromdate") String fromdate,
                                          @RequestParam("todate") String todate,
                                          @RequestParam("top") int top) {
        List<Monthly_booking> monthly_bookingList=new ArrayList<>();
        SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd");
        try{
            Date fromdate2 = dt.parse(fromdate);
            Date todate2 = dt.parse(todate);
            monthly_bookingList = monthly_bookingService.getMonthly_bookingByDate(fromdate2, todate2, top);
        }catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(monthly_bookingList);
    }
}
