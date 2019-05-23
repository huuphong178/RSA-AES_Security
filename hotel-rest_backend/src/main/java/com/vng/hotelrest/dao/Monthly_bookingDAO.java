package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Monthly_booking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface Monthly_bookingDAO extends JpaRepository<Monthly_booking, Long> {
    @Query(value = "select * from Monthly_booking where time between :fromdate and :todate limit :top", nativeQuery = true)
    List<Monthly_booking> getMonthly_bookingByDate(@Param("fromdate") Date fromdate, @Param("todate") Date todate, @Param("top") int top);
}
