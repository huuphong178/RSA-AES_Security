//package com.vng.hotelrest.dao.impl;
//
//import com.vng.hotelrest.dao.RoomDAO;
//import com.vng.hotelrest.entity.Room;
//import org.hibernate.Criteria;
//import org.hibernate.Session;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.data.domain.Example;
//import org.springframework.data.domain.Page;
//import org.springframework.data.domain.Pageable;
//import org.springframework.data.domain.Sort;
//import org.springframework.stereotype.Repository;
//
//import java.util.List;
//import java.util.Optional;
//
//import org.hibernate.SessionFactory;
//import org.springframework.transaction.annotation.Transactional;
//
//import javax.persistence.EntityManager;
//import javax.persistence.EntityManagerFactory;
//import javax.persistence.PersistenceContext;
//import javax.persistence.criteria.CriteriaBuilder;
//import javax.persistence.criteria.CriteriaQuery;
//import javax.persistence.criteria.Root;
//
//
//@Repository
//public class RoomDAOImpl implements RoomDAO {
//    @Override
//    public Room getOne(String roomid) {
//        return null;
//    }
//
//    @Override
//    public List<Room> findAll() {
//        return null;
//    }
//
//    @Override
//    public List<Room> findAll(Sort sort) {
//        return null;
//    }
//
//    @Override
//    public Page<Room> findAll(Pageable pageable) {
//        return null;
//    }
//
//    @Override
//    public List<Room> findAllById(Iterable<Long> iterable) {
//        return null;
//    }
//
//    @Override
//    public long count() {
//        return 0;
//    }
//
//    @Override
//    public void deleteById(Long aLong) {
//
//    }
//
//    @Override
//    public void delete(Room room) {
//
//    }
//
//    @Override
//    public void deleteAll(Iterable<? extends Room> iterable) {
//
//    }
//
//    @Override
//    public void deleteAll() {
//
//    }
//
//    @Override
//    public <S extends Room> S save(S s) {
//        return null;
//    }
//
//    @Override
//    public <S extends Room> List<S> saveAll(Iterable<S> iterable) {
//        return null;
//    }
//
//    @Override
//    public Optional<Room> findById(Long aLong) {
//        return Optional.empty();
//    }
//
//    @Override
//    public boolean existsById(Long aLong) {
//        return false;
//    }
//
//    @Override
//    public void flush() {
//
//    }
//
//    @Override
//    public <S extends Room> S saveAndFlush(S s) {
//        return null;
//    }
//
//    @Override
//    public void deleteInBatch(Iterable<Room> iterable) {
//
//    }
//
//    @Override
//    public void deleteAllInBatch() {
//
//    }
//
//    @Override
//    public Room getOne(Long aLong) {
//        return null;
//    }
//
//    @Override
//    public <S extends Room> Optional<S> findOne(Example<S> example) {
//        return Optional.empty();
//    }
//
//    @Override
//    public <S extends Room> List<S> findAll(Example<S> example) {
//        return null;
//    }
//
//    @Override
//    public <S extends Room> List<S> findAll(Example<S> example, Sort sort) {
//        return null;
//    }
//
//    @Override
//    public <S extends Room> Page<S> findAll(Example<S> example, Pageable pageable) {
//        return null;
//    }
//
//    @Override
//    public <S extends Room> long count(Example<S> example) {
//        return 0;
//    }
//
//    @Override
//    public <S extends Room> boolean exists(Example<S> example) {
//        return false;
//    }
//
////    @Autowired
////    private EntityManagerFactory entityManagerFactory;
////
////    public List getAllRooms() {
////        Session session = entityManagerFactory.unwrap(SessionFactory.class).openSession();
////        CriteriaBuilder builder = session.getCriteriaBuilder();
////        CriteriaQuery criteria = builder.createQuery(Room.class);
////        Root contactRoot = criteria.from(Room.class);
////        criteria.select(contactRoot);
////        return session.createQuery(criteria).getResultList();
////
////    }
//
//}
