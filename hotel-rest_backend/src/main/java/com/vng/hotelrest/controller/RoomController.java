package com.vng.hotelrest.controller;

import com.google.gson.Gson;
import com.vng.hotelrest.entity.Room;
import com.vng.hotelrest.exception.ResourceNotFoundException;
import com.vng.hotelrest.service.RoomService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api")
@Controller
public class RoomController {
    @Autowired
    private Gson gson;
    @Autowired
    private RoomService roomService;
    LinkedHashMap<String, Object> response = new LinkedHashMap<String, Object>();

    @RequestMapping(value = "/rooms", method = RequestMethod.GET, produces = "application/json")
    public String getAll() {
        List<Room> roomList =new ArrayList<>();
        try {
            roomList =  roomService.getAll();
            response.put("rooms", roomList);
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(roomList);
    }
    @GetMapping(value = "/room/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Room> getOne(@PathVariable("id") String id) {
        System.out.println("Fetching User with id " + id);
        Room room = roomService.getOne(id);
        if (room == null) {
            return new ResponseEntity<Room>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<Room>(room, HttpStatus.OK);
    }

    @PostMapping(value="/room",headers="Accept=application/json")
    public ResponseEntity<Room> createRoom(@RequestBody Room room, UriComponentsBuilder ucBuilder){
        System.out.println("Creating User "+room.getRoomName());
        Room roomret =roomService.createRoom(room);
        if (roomret==null) {
            return new ResponseEntity<Room>(HttpStatus.BAD_REQUEST);
        }
        //HttpHeaders headers = new HttpHeaders();
        //headers.setLocation(ucBuilder.path("/room/{id}").buildAndExpand(room.getRoomID()).toUri());
        return new ResponseEntity<Room> (roomret, HttpStatus.OK);
    }
    @PutMapping(value="/room", headers="Accept=application/json")
    public ResponseEntity<Room> updateRoom(@RequestBody Room roomreq)
    {
        Room room = roomService.getOne(roomreq.getRoomID());
        if (room==null) {
            return new ResponseEntity<Room>(HttpStatus.NOT_FOUND);
        }
        Room roomret = roomService.update(roomreq, roomreq.getRoomID());
        if (roomret==null) {
            return new ResponseEntity<Room>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<Room>(roomret,HttpStatus.OK);
    }
    @DeleteMapping(value="/{id}", headers ="Accept=application/json")
    public ResponseEntity<Room> deleteRooom(@PathVariable("id") String id){
        Room room = roomService.getOne(id);
        if (room == null) {
            return new ResponseEntity<Room>(HttpStatus.NOT_FOUND);
        }
        roomService.delete(id);
        return new ResponseEntity<Room>(HttpStatus.OK);
    }
    @GetMapping(value = "/roomName", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getRoomName() {
        List<String> roomname =new ArrayList<>();
        try {
            roomname =  roomService.getRoomName();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(roomname);
    }
    @GetMapping(value = "/roomStatus", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getRoomStatus() {
        List<Integer> roomstatus =new ArrayList<>();
        try {
            roomstatus =  roomService.getRoomStatus();
        } catch (Exception e) {
            System.out.println(e);
        }
        return gson.toJson(roomstatus);
    }


}
