package com.vng.hotelrest.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "Weekly_booking")
@EntityListeners(AuditingEntityListener.class)
public class Weekly_booking {
    @Id
    @Column(name = "time")
    private Date time;
    @Column(name = "amount")
    private Long Amount;

    public Weekly_booking(Date time, Long amount) {
        this.time = time;
        Amount = amount;
    }

    public Weekly_booking() {
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
