package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Room;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface RoomDAO extends JpaRepository<Room, Long> {
    @Query("select c from Room c where c.roomID=:roomid")
    Room getOne(@Param("roomid") String roomid);
    @Modifying
    @Query("delete from Room r where roomID=:roomid")
    void deletebyRoomId(@Param("roomid") String roomid);
}
