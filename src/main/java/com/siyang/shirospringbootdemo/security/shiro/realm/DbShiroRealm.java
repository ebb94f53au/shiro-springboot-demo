package com.siyang.shirospringbootdemo.security.shiro.realm;

import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author siyang
 * @create 2020-01-12 20:15
 * 只需要登录验证，所以只需要继承AuthenticatingRealm
 */
public class DbShiroRealm extends AuthenticatingRealm {

    @Autowired
    private UserService userService;


    /**
     * 限定这个Realm只支持UsernamePasswordToken
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }



    /**
     * 验证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken =(UsernamePasswordToken) authenticationToken;
        String username = usernamePasswordToken.getUsername();
        User user = userService.getUserByUsername(username);
        if(user == null) {
            // 账号不存在
            throw new AuthenticationException();
        }
        return new SimpleAuthenticationInfo(user,user.getPassword(),"dbRealm");
    }
}
