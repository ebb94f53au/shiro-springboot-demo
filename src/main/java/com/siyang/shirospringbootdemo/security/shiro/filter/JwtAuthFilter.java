package com.siyang.shirospringbootdemo.security.shiro.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.siyang.shirospringbootdemo.security.token.JwtToken;
import com.siyang.shirospringbootdemo.security.token.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.http.HttpStatus;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author siyang
 * @create 2020-01-12 20:40
 * jwt过滤器
 * 不能写@bean之类的直接，不能交给spring管理
 */
@Slf4j
public class JwtAuthFilter extends BasicHttpAuthenticationFilter {

    private JwtTokenProvider jwtTokenProvider;


    public JwtAuthFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }


    /**
     *父类会在请求进入拦截器后调用该方法，返回true则继续，返回false则会调用onAccessDenied()。这里在不通过时，还调用了isPermissive()方法，我们后面解释。
     * @param request
     * @param response
     * @param mappedValue
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {

        boolean allowed = false;
        try {
            //内部的方法会执行createToken
            allowed = executeLogin(request, response);
        } catch(IllegalStateException e){ //not found any token
            log.error("Not found any token");
        }catch (Exception e) {
            log.error("Error occurs when login", e);
        }
        return allowed || super.isPermissive(mappedValue);
    }

    /**
     *  这里重写了父类的方法，使用我们自己定义的Token类，提交给shiro。这个方法返回null的话会直接抛出异常，进入isAccessAllowed（）的异常处理逻辑。
     * @param request
     * @param response
     * @return
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        //从request头中取出token
        String token = jwtTokenProvider.getToken((HttpServletRequest) request);
        //如果token不为空 并且token验证合格
        if(token!=null){
            // 返回的JWTtoken 会被JwtShiroRealm 进行解析
            return new JwtToken(token);
        }

        return null;
    }


    /**
     * 如果这个Filter在之前isAccessAllowed（）方法中返回false,则会进入这个方法。我们这里直接返回错误的response
     * @param servletRequest
     * @param servletResponse
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {

        HttpServletResponse res = (HttpServletResponse)servletResponse;
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setStatus(HttpServletResponse.SC_OK);
        res.setCharacterEncoding("UTF-8");
        PrintWriter writer = res.getWriter();
        Map<String, Object> map= new HashMap<>();
        map.put("status", 401);
        LocalDateTime now = LocalDateTime.now();
        now.format(DateTimeFormatter.ISO_DATE_TIME);

        map.put("timestamp", now.toString());
        map.put("message", "身份认证失败");
        writer.write(JSON.toJSONString(map));
        writer.close();
        return false;
    }
}
