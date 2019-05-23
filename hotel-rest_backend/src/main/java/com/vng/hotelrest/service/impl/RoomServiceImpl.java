package com.vng.hotelrest.service.impl;

import com.vng.hotelrest.dao.RoomDAO;
import com.vng.hotelrest.entity.Room;
import com.vng.hotelrest.service.RoomService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
public class RoomServiceImpl implements RoomService {

    @Autowired
    RoomDAO roomDAO;
    @Override
    public List<Room> getAll() {
        return roomDAO.findAll();
    }
    @Override
    public Room createRoom(Room room) {
        return roomDAO.save(room);
    }
    @Override
    public Room getOne(String id) {
        return roomDAO.getOne(id);
    }

    @Override
    public Room update(Room room, String roomid) {
        return roomDAO.save(room);
    }

    @Override
    public void delete(String id) {
        roomDAO.deletebyRoomId(id);
    }
    @Override
    public List<String> getRoomName(){
        List<String> ret = new ArrayList<>();
        List<Room> rooms= roomDAO.findAll();
        for (Room room: rooms
             ) {
            ret.add(room.getRoomName());
        }
        return ret;
    }
    @Override
    public List<Integer> getRoomStatus(){
        List<Integer> ret = new ArrayList<>();
        List<Room> rooms= roomDAO.findAll();
        for (Room room: rooms
        ) {
            ret.add(room.getIsActive());
        }
        return ret;
    }
}
