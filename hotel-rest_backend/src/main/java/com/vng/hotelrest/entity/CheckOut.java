package com.vng.hotelrest.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "CheckOut")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(value = {"checkOutDate"},
        allowGetters = true)
public class CheckOut implements Serializable {
    @Id
    @Column(name = "bookingID")
    private String bookingID;
    @Column(name = "roomID")
    private String roomID;
    @Column(name = "totalAmount")
    private Long totalAmount;
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "checkOutDate",nullable = false, updatable = false)
    @CreatedDate
    private Date checkOutDate;

    public CheckOut() {
    }

    public CheckOut(String bookingID, String roomID, Long totalAmount, Date checkOutDate) {
        this.bookingID = bookingID;
        this.roomID = roomID;
        this.totalAmount = totalAmount;
        this.checkOutDate = checkOutDate;
    }

    public String getBookingID() {
        return bookingID;
    }

    public void setBookingID(String bookingID) {
        this.bookingID = bookingID;
    }

    public String getRoomID() {
        return roomID;
    }

    public void setRoomID(String roomID) {
        this.roomID = roomID;
    }

    public Long getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Long totalAmount) {
        this.totalAmount = totalAmount;
    }

    public Date getCheckOutDate() {
        return checkOutDate;
    }

    public void setCheckOutDate(Date checkOutDate) {
        this.checkOutDate = checkOutDate;
    }
}
