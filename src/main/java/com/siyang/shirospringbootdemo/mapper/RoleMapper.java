package com.siyang.shirospringbootdemo.mapper;

import com.siyang.shirospringbootdemo.bean.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author siyang
 * @create 2020-05-29 10:13
 */
@Repository
public interface RoleMapper extends JpaRepository<Role,Integer> {
}
