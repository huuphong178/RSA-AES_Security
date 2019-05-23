package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Daily_booking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface Daily_bookingDAO extends JpaRepository<Daily_booking,Long> {
    @Query(value = "select * from Daily_booking where time between :fromdate and :todate limit :top", nativeQuery = true)
    List<Daily_booking> getDaily_bookings(@Param("fromdate") Date fromdate, @Param("todate") Date todate, @Param("top") int top);
}
