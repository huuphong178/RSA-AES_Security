package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.CheckOut;
import com.vng.hotelrest.service.CheckOutService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class CheckOutController {
    @Autowired
    private Gson gson;
    @Autowired
    private CheckOutService checkOutService;
    @RequestMapping(value = "/checkOuts", method = RequestMethod.GET, produces = "application/json")
    public String getAll() {
        List<CheckOut> checkOutList =new ArrayList<>();
        try {
            checkOutList =  checkOutService.getAll();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(checkOutList);
    }
    @GetMapping(value = "/getHotelTotal", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getchartHotelTotal() {
        List<Integer> chartHotelTotal =new ArrayList<>();
        try {
            chartHotelTotal =  checkOutService.getchartHotelTotal();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(chartHotelTotal);
    }
}
