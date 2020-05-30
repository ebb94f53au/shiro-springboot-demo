package com.siyang.shirospringbootdemo.security.controller;

import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.security.config.SecurityProperties;
import com.siyang.shirospringbootdemo.security.token.JwtTokenProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author siyang
 * @create 2020-05-29 11:26
 */
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private SecurityProperties properties;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<Object> login(User user){
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(user.getUsername(), user.getPassword());
        // 登录验证
        subject.login(usernamePasswordToken);

        // 生成token
        String token = jwtTokenProvider.createToken(user.getUsername());
        // 将token放入redis

        Map<String,Object> authInfo = new HashMap<String,Object>(1){{
            put("token", properties.getTokenStartWith() + token);
        }};

        return ResponseEntity.ok(authInfo);
    }

}
