package com.siyang.shirospringbootdemo.mapper;

import com.siyang.shirospringbootdemo.bean.Role;
import com.siyang.shirospringbootdemo.bean.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author siyang
 * @create 2020-05-29 10:13
 */
@Repository
public interface UserMapper extends JpaRepository<User,Integer> {

    public User getUserByUsername(String username);
}
