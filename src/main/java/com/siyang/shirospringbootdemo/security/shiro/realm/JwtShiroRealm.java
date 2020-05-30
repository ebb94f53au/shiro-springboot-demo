package com.siyang.shirospringbootdemo.security.shiro.realm;

import com.siyang.shirospringbootdemo.bean.Permission;
import com.siyang.shirospringbootdemo.bean.Role;
import com.siyang.shirospringbootdemo.bean.User;
import com.siyang.shirospringbootdemo.common.exception.BadRequestException;
import com.siyang.shirospringbootdemo.security.token.JwtToken;
import com.siyang.shirospringbootdemo.security.token.JwtTokenProvider;
import com.siyang.shirospringbootdemo.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author siyang
 * @create 2020-01-14 18:13
 * 需要jwt验证和授权，所以需要继承AuthorizingRealm
 */
public class JwtShiroRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;


    /**
     * 限定这个Realm只支持我们自定义的JWT Token
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }



    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 这里可以优化，事先将权限信息存入jwt中，只需要直接解析就可以赋值角色与权限
        JwtToken primaryPrincipal = (JwtToken)principalCollection.getPrimaryPrincipal();
        String token = primaryPrincipal.getToken();
        String username = jwtTokenProvider.parseToken(token);
        User user = userService.getUserByUsername(username);
        Set<Role> roles = user.getRoles();
        Set<String> roleSet = new HashSet<>();
        Set<String> permissionSet = new HashSet<>();
        for (Role role : roles) {
            roleSet.add(role.getName());
            // 将角色下所有权限都存入permissions
            Set<Permission> p = role.getPermissions();
            for (Permission permission : p) {
                permissionSet.add(permission.getPermissionValue());
            }
        }

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setRoles(roleSet);
        simpleAuthorizationInfo.setStringPermissions(permissionSet);
        return simpleAuthorizationInfo;

    }

    /**
     * token登录，每次请求都要判断路径
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        JwtToken token = (JwtToken) authenticationToken;
        // 如果解析jwt有问题会跳出
        String username = jwtTokenProvider.parseToken(token.getToken());
        User user = userService.getUserByUsername(username);
        if(user == null) {
            // 账号不存在
            throw new AuthenticationException();
        }
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(token,token,"jwtRealm");
        return simpleAuthenticationInfo;
    }
}
