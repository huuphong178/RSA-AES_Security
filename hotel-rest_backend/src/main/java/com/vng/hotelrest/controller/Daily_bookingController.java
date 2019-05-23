package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.Auth;
import com.vng.hotelrest.entity.Daily_booking;
import com.vng.hotelrest.service.AuthService;
import com.vng.hotelrest.service.Daily_bookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class Daily_bookingController {
    @Autowired
    private Gson gson;
    @Autowired
    private Daily_bookingService daily_bookingService;
    @GetMapping(value = "/getDaily_booking", produces = MediaType.APPLICATION_JSON_VALUE,params = {"fromdate","todate","top"})
    @ResponseBody
    public String getDaily_bookingByDate(@RequestParam("fromdate") String fromdate,
                                                                @RequestParam("todate") String todate,
                                                                @RequestParam("top") int top) {
        SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd");
        List<Daily_booking> daily_bookingList=new ArrayList<>();
        try{
            Date fromdate2 = dt.parse(fromdate);
            Date todate2 = dt.parse(todate);
            daily_bookingList=daily_bookingService.getDaily_bookingByDate(fromdate2, todate2, top);
        }catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(daily_bookingList);
    }
}
