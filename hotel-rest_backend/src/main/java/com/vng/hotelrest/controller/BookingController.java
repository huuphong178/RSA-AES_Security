package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.Booking;
import com.vng.hotelrest.entity.CheckOut;
import com.vng.hotelrest.entity.Monthly_booking;
import com.vng.hotelrest.service.BookingService;
import com.vng.hotelrest.service.CheckOutService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.persistence.Entity;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class BookingController {
    @Autowired
    private Gson gson;
    @Autowired
    private BookingService bookingService;
    @RequestMapping(value = "/bookings", method = RequestMethod.GET, produces = "application/json")
    public String getAll() {
        List<Booking> bookingList =new ArrayList<>();
        try {
            bookingList =  bookingService.getAll();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(bookingList);
    }
//    @GetMapping(value="/getRoomTypeChart/{month}/{year}",headers="Accept=application/json")
//    public String getRoomTypeChart(@PathVariable int month,@PathVariable int year){
//        List<Integer> ret=bookingService.getRoomTypeChart(month,year);
//        return gson.toJson(ret);
//        //return "";
//    }
    @GetMapping(value="/getTotalBooking",headers="Accept=application/json")
    public String getCountBooking(){
        Long ret=bookingService.getCountBooking();
        return "{\"count\":"+ret+"}";
        //return "";
    }
    @GetMapping(value="/getCountBooking",headers="Accept=application/json")
    public String getCountBooking(@RequestParam(required = false) String month,@RequestParam(required = false) String trimester, @RequestParam String year){
        System.out.println(month);
        Long ret= Long.valueOf(0);
        if(month == null && trimester == null){
            ret=bookingService.getCountBooking(Integer.parseInt(year));
        }
        else if(month == null && trimester !=null){
            ret=bookingService.getCountBookingTri(Integer.parseInt(trimester),Integer.parseInt(year));
        }
        else ret=bookingService.getCountBooking(Integer.parseInt(month),Integer.parseInt(year));
        return "{\"count\":"+ret+"}";
    }
    @GetMapping(value="/getRoomTypeChartAll",headers="Accept=application/json")
    public String getRoomTypeChart(){
        List<Integer> ret=bookingService.getRoomTypeChartAll();
        return gson.toJson(ret);
    }
    @GetMapping(value="/getRoomTypeChart",headers="Accept=application/json")
    public String getRoomTypeChart(@RequestParam(required = false) String month,@RequestParam(required = false) String trimester, @RequestParam String year){
        List<Integer> ret= new ArrayList<>();
        if(month == null && trimester == null){
            ret=bookingService.getRoomTypeChart(Integer.parseInt(year));
        }
        else if(month == null && trimester !=null){
            ret=bookingService.getRoomTypeChartTri(Integer.parseInt(trimester),Integer.parseInt(year));
        }
        else ret=bookingService.getRoomTypeChart(Integer.parseInt(month),Integer.parseInt(year));
        return gson.toJson(ret);
    }
}
