package com.promise.config;

import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.promise.controller.Code;
import com.promise.controller.Result;
import com.promise.exception.TokenException;
import com.promise.service.impl.UserServiceImpl;
import com.promise.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 自定义登录成功逻辑
 */
@Component
public class MyAuthenticationAccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserServiceImpl userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException,
            ServletException, TokenException {
        // 根据userDetailsService生成token
        String username = authentication.getName();
        String token = jwtTokenUtil.generateToken(userService.loadUserByUsername(username));
        if (StrUtil.isEmpty(token)) throw new TokenException("token生成失败");

        // 设置返回值
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("tokenHead", tokenHead);
        Result result = new Result(Code.CODE_SUCCESS, "登录成功", data);

        // 设置返回消息类型
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json;charset=UTF-8");

        // 返回给前端
        response.getWriter().write(new ObjectMapper().writeValueAsString(result));
    }
}
