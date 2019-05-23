package com.vng.hotelrest.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "Booking")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(value = {"bookingDate"},
        allowGetters = true)
public class Booking implements Serializable {
    @Id
    @Column(name = "bookingID")
    private String bookingID;
    @Column(name = "customerID")
    private String customerID;
    @Column(name = "roomID")
    private String roomID;
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "bookingDate",nullable = false, updatable = false)
    @CreatedDate
    private Date bookingDate;
    @Column(name = "fromDate")
    private String fromDate;
    @Column(name = "toDate")
    private String toDate;
    @Column(name = "bookingStatus")
    private int bookingStatus;

    public Booking() {
    }

    public Booking(String bookingID, String customerID, String roomID, Date bookingDate, String fromDate, String toDate, int bookingStatus) {
        this.bookingID = bookingID;
        this.customerID = customerID;
        this.roomID = roomID;
        this.bookingDate = bookingDate;
        this.fromDate = fromDate;
        this.toDate = toDate;
        this.bookingStatus = bookingStatus;
    }

    public String getBookingID() {
        return bookingID;
    }

    public void setBookingID(String bookingID) {
        this.bookingID = bookingID;
    }

    public String getCustomerID() {
        return customerID;
    }

    public void setCustomerID(String customerID) {
        this.customerID = customerID;
    }

    public String getRoomID() {
        return roomID;
    }

    public void setRoomID(String roomID) {
        this.roomID = roomID;
    }

    public Date getBookingDate() {
        return bookingDate;
    }

    public void setBookingDate(Date bookingDate) {
        this.bookingDate = bookingDate;
    }

    public String getFromDate() {
        return fromDate;
    }

    public void setFromDate(String fromDate) {
        this.fromDate = fromDate;
    }

    public String getToDate() {
        return toDate;
    }

    public void setToDate(String toDate) {
        this.toDate = toDate;
    }

    public int getBookingStatus() {
        return bookingStatus;
    }

    public void setBookingStatus(int bookingStatus) {
        this.bookingStatus = bookingStatus;
    }
}
