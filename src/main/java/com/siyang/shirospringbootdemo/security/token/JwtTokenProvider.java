package com.siyang.shirospringbootdemo.security.token;

import com.siyang.shirospringbootdemo.security.config.SecurityProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;

/**
 * @author siyang
 * @create 2020-01-12 20:50
 * JWT-TOKEN 提供类
 */
@Slf4j
@Component
public class JwtTokenProvider implements InitializingBean {

    @Autowired
    private SecurityProperties properties;
    private static final String AUTHORITIES_KEY ="auth";
    private Key key;
    /**
     * 实例化对前会调用此方法,需要Spring的环境
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] decode = Decoders.BASE64.decode(properties.getBase64Secret());
        this.key= Keys.hmacShaKeyFor(decode);
    }

    /**
     * 创建token
     * @return
     */
    public String createToken(String username){

        long now = new Date().getTime();
        Date date = new Date(now + properties.getTokenValidityInSeconds());


        return Jwts.builder().setSubject(username).setExpiration(date).signWith(key, SignatureAlgorithm.HS512).compact();

    }

    /**
     * 验证token
     * @return
     */
    public boolean vaildateToken (String token){

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT signature.");
            e.printStackTrace();
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            e.printStackTrace();
        }
        return false;

    }

    /**
     * 根据token 解析出username
     * @param token
     * @return
     */
    public String parseToken(String token){
        Claims body = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        String username = body.getSubject();
        return username;

    }
    /**
     * 从request中获取token
     * @param request
     * @return
     */
    public String getToken(HttpServletRequest request){
        String header = request.getHeader(properties.getHeader());
        if(header != null && header.startsWith(properties.getTokenStartWith())){

            header=header.substring(properties.getTokenStartWith().length());
        }
        return header;
    }

}
