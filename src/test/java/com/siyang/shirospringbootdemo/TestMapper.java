package com.siyang.shirospringbootdemo;

import com.siyang.shirospringbootdemo.bean.Permission;
import com.siyang.shirospringbootdemo.bean.Role;
import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.mapper.PermissionMapper;
import com.siyang.shirospringbootdemo.mapper.RoleMapper;
import com.siyang.shirospringbootdemo.mapper.UserMapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * @author siyang
 * @create 2020-05-29 10:16
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class TestMapper {
    @Autowired
    UserMapper userMapper;
    @Autowired
    RoleMapper roleMapper;
    @Autowired
    PermissionMapper permissionMapper;

    @Test
    public void testjpa(){
        Permission permission = new Permission();
        permission.setPermissionValue("write");

        Optional<Role> byId = roleMapper.findById(1);
        Role role = byId.get();
        Set<Permission> permissions = role.getPermissions();
        permissions.add(permission);
        System.out.println(role);

        permissionMapper.save(permission);
        roleMapper.save(role);

        Optional<User> byId1 = userMapper.findById(1);
        User user = byId1.get();
        System.out.println(user);


    }
}
