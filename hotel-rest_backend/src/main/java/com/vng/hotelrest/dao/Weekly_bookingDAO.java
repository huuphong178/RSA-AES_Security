package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Weekly_booking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface Weekly_bookingDAO extends JpaRepository<Weekly_booking, Long> {
    @Query(value = "select * from Weekly_booking where time between :fromdate and :todate limit :top", nativeQuery = true)
    List<Weekly_booking> getWeekly_bookingByDate(@Param("fromdate") Date fromdate, @Param("todate") Date todate, @Param("top") int top);
}
