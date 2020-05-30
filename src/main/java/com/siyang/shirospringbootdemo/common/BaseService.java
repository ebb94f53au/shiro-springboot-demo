package com.siyang.shirospringbootdemo.common;

import java.util.List;

/**
 * @author siyang
 * @create 2020-05-29 10:56
 */
public interface BaseService<S> {

    // 增加
    public void insert(S s);
    // 删除
    public void delete(Integer id);
    // 修改
    public S update(S s);
    // 根据id查询某一个
    public S findOneById(Integer id);
    // 查询所有
    public List<S> findAll();
}
