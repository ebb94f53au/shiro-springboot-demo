package com.siyang.shirospringbootdemo.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author siyang
 * @create 2020-05-29 10:00
 */
@Entity
@ToString
@Data
@Table(name="se_user")
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;

    @JsonIgnore
    @ManyToMany(targetEntity = Role.class,fetch=FetchType.EAGER)
    @JoinTable(name="se_user_role",
            joinColumns = {@JoinColumn(name = "userId",referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "roleId", referencedColumnName = "id")}
    )
    private Set<Role> roles = new HashSet<>();

}
