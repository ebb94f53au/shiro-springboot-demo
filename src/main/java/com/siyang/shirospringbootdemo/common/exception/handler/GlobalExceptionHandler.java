package com.siyang.shirospringbootdemo.common.exception.handler;

import com.fasterxml.jackson.core.JsonParseException;
import com.siyang.shirospringbootdemo.common.exception.BadRequestException;
import io.jsonwebtoken.MalformedJwtException;
import io.netty.util.internal.ThrowableUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.CredentialsException;
import org.apache.shiro.authz.AuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @author siyang
 * @create 2020-01-13 13:45
 * 全局异常处理器
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {



    @ExceptionHandler(value = AuthenticationException.class)
    public ResponseEntity incorrectCredentialsException(AuthenticationException e){
        log.error("用户名或密码不正确");
        return buildResponseEntity(ApiError.error("用户名或密码不正确"));
    }

    @ExceptionHandler(value = AuthorizationException.class)
    public ResponseEntity incorrectCredentialsException(AuthorizationException e){
        log.error("没有权限");
        return buildResponseEntity(ApiError.error("没有权限"));
    }


    /**
     * 处理自定义异常
     * @param e
     * @return
     */
    @ExceptionHandler(value = BadRequestException.class)
    public ResponseEntity badRequestException(BadRequestException e){
        // 打印堆栈信息
//        log.error(ThrowableUtil.getStackTrace(e));
        return buildResponseEntity(ApiError.error(e.getStatus(),e.getMessage()));

    }
    /**
     * 统一返回
     */
    private ResponseEntity<ApiError> buildResponseEntity(ApiError apiError) {
        return new ResponseEntity<>(apiError, HttpStatus.valueOf(apiError.getStatus()));
    }
}
