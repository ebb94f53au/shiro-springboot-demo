package com.siyang.shirospringbootdemo.security.token;

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * @author siyang
 * @create 2020-01-14 17:48
 * 封装的JwtToken对象
 */
public class JwtToken implements HostAuthenticationToken {
    private String token;
    private String host;
    public JwtToken(String token) {
        this(token, null);
    }
    public JwtToken(String token, String host) {
        this.token = token;
        this.host = host;
    }
    public String getToken(){
        return this.token;
    }
    public String getHost() {
        return host;
    }
    @Override
    public Object getPrincipal() {
        return token;
    }
    @Override
    public Object getCredentials() {
        return token;
    }
    @Override
    public String toString(){
        return token + ':' + host;
    }
}
