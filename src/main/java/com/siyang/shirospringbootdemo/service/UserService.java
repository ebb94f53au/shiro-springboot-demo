package com.siyang.shirospringbootdemo.service;

import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.common.BaseService;

/**
 * @author siyang
 * @create 2020-05-29 10:54
 */
public interface UserService extends BaseService<User> {

    public User getUserByUsername(String username);

}
