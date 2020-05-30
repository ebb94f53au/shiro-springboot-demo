package com.siyang.shirospringbootdemo.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author siyang
 * @create 2020-01-12 14:45
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")//从yml配置文件中获取配置的属性
public class SecurityProperties {

    /** Request Headers ： Authorization */
    private String header;

    /** 令牌前缀，最后留个空格 Bearer */
    private String tokenStartWith;

    /** 必须使用最少88位的Base64对该令牌进行编码 */
    private String base64Secret;

    /** 令牌过期时间 此处单位/毫秒 */
    private Long tokenValidityInSeconds;

    /** 在线用户 key，根据 key 查询 redis 中在线用户的数据 */
    private String onlineKey;

    /** 验证码 key */
    private String codeKey;

    public String getTokenStartWith() {
        return tokenStartWith + " ";
    }

}
