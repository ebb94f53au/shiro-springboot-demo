package com.siyang.shirospringbootdemo.bean;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author siyang
 * @create 2020-05-29 10:04
 */
@Entity
@Data
@Table(name="se_permission")
public class Permission implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "permissionValue")
    private String permissionValue;
}
