package com.promise.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.promise.controller.Code;
import com.promise.controller.Result;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义未登录逻辑
 */
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        Result data = new Result(Code.CODE_FAIL, "未登录");

        // 设置返回消息类型
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json;charset=UTF-8");

        // 返回给前端
        response.getWriter().write(new ObjectMapper().writeValueAsString(data));
    }
}
