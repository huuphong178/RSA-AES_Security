package com.vng.hotelrest.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "Room")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(value = {"createDate","updateDate"},
        allowGetters = true)
public class Room implements Serializable {
    @Id
    @Column(name = "roomID")
    private String roomID;
    @Column(name = "roomName")
    private String roomName;
    @Column(name = "roomType")
    private int roomType;
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "createDate",nullable = false, updatable = false)
    @CreatedDate
    private Date createDate;
    @Column(name = "isActive")
    private int isActive;
    @Column(name = "description")
    private String description;

    @Column(name="updateDate",nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    @LastModifiedDate
    private Date updateDate;

    public Date getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(Date updateDate) {
        this.updateDate = updateDate;
    }

    public Room(String roomID, String roomName, int roomType, Date createDate, int isActive, String description) {
        this.roomID = roomID;
        this.roomName = roomName;
        this.roomType = roomType;
        this.createDate = createDate;
        this.isActive = isActive;
        this.description = description;
    }

    public Room() {
    }

    public String getRoomID() {
        return roomID;
    }

    public void setRoomID(String roomID) {
        this.roomID = roomID;
    }

    public String getRoomName() {
        return roomName;
    }

    public void setRoomName(String roomName) {
        this.roomName = roomName;
    }

    public int getRoomType() {
        return roomType;
    }

    public void setRoomType(int roomType) {
        this.roomType = roomType;
    }

    public Date getCreateDate() {
        return createDate;
    }

    public void setCreateDate(Date createDate) {
        this.createDate = createDate;
    }

    public int getIsActive() {
        return isActive;
    }

    public void setIsActive(int isActive) {
        this.isActive = isActive;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
