package com.vng.hotelrest.service;

import com.vng.hotelrest.entity.Room;

import java.util.List;

public interface RoomService{
    List<Room> getAll();
    Room createRoom(Room room);
    Room getOne(String id);
    Room update(Room room, String roomid);
    void delete(String id);
    List<String> getRoomName();
    List<Integer> getRoomStatus();
}
