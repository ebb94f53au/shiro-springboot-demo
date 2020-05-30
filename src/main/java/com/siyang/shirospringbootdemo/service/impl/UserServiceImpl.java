package com.siyang.shirospringbootdemo.service.impl;

import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.common.exception.BadRequestException;
import com.siyang.shirospringbootdemo.mapper.UserMapper;
import com.siyang.shirospringbootdemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author siyang
 * @create 2020-05-29 11:00
 */
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserMapper userMapper;

    @Override
    public void insert(User user) {
        userMapper.save(user);
    }

    @Override
    public void delete(Integer id) {
        userMapper.deleteById(id);
    }

    @Override
    public User update(User user) {
        return userMapper.save(user);
    }

    @Override
    public User findOneById(Integer id) {
        Optional<User> op = userMapper.findById(id);
        if(op.isPresent())
            return op.get();
        else
            return null;
    }

    @Override
    public List<User> findAll() {
        List<User> all = userMapper.findAll();
        return all;
    }

    @Override
    public User getUserByUsername(String username) {
        User user = userMapper.getUserByUsername(username);
        return user;
    }
}
