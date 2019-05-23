package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Booking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;


@Repository
public interface BookingDAO extends JpaRepository<Booking, Long> {
    @Query(value = "select count(*) as countBooking from hotel.Booking where :month = month(bookingDate) and :year = year(bookingDate)", nativeQuery = true)
    Long getCountBooking(@Param("month") Integer month, @Param("year") Integer year);
    @Query(value = "select count(*) as countBooking from hotel.Booking where :year = year(bookingDate)", nativeQuery = true)
    Long getCountBooking(@Param("year") Integer year);
    @Query(value = "select count(*) as countBooking from hotel.Booking where month(bookingDate) <= :trimester *3 and month(bookingDate) > :trimester *3-3 and :year = year(bookingDate)", nativeQuery = true)
    Long getCountBookingTri(@Param("trimester") Integer trimester, @Param("year") Integer year);
}
