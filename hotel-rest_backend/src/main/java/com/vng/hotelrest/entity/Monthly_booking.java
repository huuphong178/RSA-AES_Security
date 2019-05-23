package com.vng.hotelrest.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "Monthly_booking")
@EntityListeners(AuditingEntityListener.class)
public class Monthly_booking {
    @Id
    @Column(name = "time")
    private Date time;
    @Column(name = "amount")
    private Long Amount;

    public Monthly_booking(Date time, Long amount) {
        this.time = time;
        Amount = amount;
    }

    public Monthly_booking() {
    }

    public Date getTime() {
        return time;
    }

    public void setTime(Date time) {
        this.time = time;
    }

    public Long getAmount() {
        return Amount;
    }

    public void setAmount(Long amount) {
        Amount = amount;
    }
}
