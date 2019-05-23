package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.BookingDAO;
import com.vng.hotelrest.dao.RoomDAO;
import com.vng.hotelrest.entity.Booking;
import com.vng.hotelrest.entity.Room;
import com.vng.hotelrest.service.BookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Service
@Transactional
public class BookingServiceImpl implements BookingService {
    @Autowired
    BookingDAO bookingDAO;
    @Autowired
    RoomDAO roomDAO;
    @Override
    public List<Booking> getAll() {
        return bookingDAO.findAll();
    }

    @Override
    public List<Integer> getRoomTypeChartAll() {
        List<Room> rooms=roomDAO.findAll();
        List<Booking> bookings=bookingDAO.findAll();
        List<Integer> ret = new ArrayList<>();
        ret.add(0); ret.add(0); ret.add(0); ret.add(0);
        for (Booking booking:bookings
             ) {
            String roomid=booking.getRoomID();
                for (Room room:rooms
                     ) {
                    String roomid2=room.getRoomID();
                    if(roomid.compareTo(roomid2)==0){
                        int status = room.getRoomType()-1;
                        ret.set(status, ret.get(status)+1);
                    }

            }
        }
        return ret;
    }
    @Override
    public List<Integer> getRoomTypeChart(int month, int year) {
        List<Room> rooms=roomDAO.findAll();
        List<Booking> bookings=bookingDAO.findAll();
        List<Integer> ret = new ArrayList<>();
        ret.add(0); ret.add(0); ret.add(0); ret.add(0);
        for (Booking booking:bookings
        ) {
            String roomid=booking.getRoomID();
            Date datebooking=booking.getBookingDate();
            Calendar cal = Calendar.getInstance();
            cal.setTime(datebooking);
            int month2 = cal.get(Calendar.MONTH)+1;
            int year2=cal.get(Calendar.YEAR);
            if(month==month2 && year== year2){
                for (Room room:rooms
                ) {
                    String roomid2=room.getRoomID();
                    if(roomid.compareTo(roomid2)==0){
                        int status = room.getRoomType()-1;
                        ret.set(status, ret.get(status)+1);
                    }
                }

            }
        }
        return ret;
    }
    @Override
    public List<Integer> getRoomTypeChart(int year) {
        List<Room> rooms=roomDAO.findAll();
        List<Booking> bookings=bookingDAO.findAll();
        List<Integer> ret = new ArrayList<>();
        ret.add(0); ret.add(0); ret.add(0); ret.add(0);
        for (Booking booking:bookings
        ) {
            String roomid=booking.getRoomID();
            Date datebooking=booking.getBookingDate();
            Calendar cal = Calendar.getInstance();
            cal.setTime(datebooking);
            int year2=cal.get(Calendar.YEAR);
            if(year== year2){
                for (Room room:rooms
                ) {
                    String roomid2=room.getRoomID();
                    if(roomid.compareTo(roomid2)==0){
                        int status = room.getRoomType()-1;
                        ret.set(status, ret.get(status)+1);
                    }
                }

            }
        }
        return ret;
    }
    @Override
    public List<Integer> getRoomTypeChartTri(int trimester, int year) {
        List<Room> rooms=roomDAO.findAll();
        List<Booking> bookings=bookingDAO.findAll();
        List<Integer> ret = new ArrayList<>();
        ret.add(0); ret.add(0); ret.add(0); ret.add(0);
        for (Booking booking:bookings
        ) {
            String roomid=booking.getRoomID();
            Date datebooking=booking.getBookingDate();
            Calendar cal = Calendar.getInstance();
            cal.setTime(datebooking);
            int month2 = cal.get(Calendar.MONTH)+1;
            int year2=cal.get(Calendar.YEAR);
            if(month2<=trimester*3 && month2>trimester*3-3 && year== year2){
                for (Room room:rooms
                ) {
                    String roomid2=room.getRoomID();
                    if(roomid.compareTo(roomid2)==0){
                        int status = room.getRoomType()-1;
                        ret.set(status, ret.get(status)+1);
                    }
                }

            }
        }
        return ret;
    }

    @Override
    public Long getCountBooking(int month, int year) {
        return bookingDAO.getCountBooking(month, year);
    }

    @Override
    public Long getCountBooking(int year) {
        return bookingDAO.getCountBooking(year);
    }

    @Override
    public Long getCountBookingTri(int trimester, int year) {
        return bookingDAO.getCountBookingTri(trimester, year);
    }

    @Override
    public Long getCountBooking() {
        return Long.valueOf(bookingDAO.findAll().size());

    }
}
