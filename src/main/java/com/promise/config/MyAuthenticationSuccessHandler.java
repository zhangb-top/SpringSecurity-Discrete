package com.promise.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.promise.controller.Code;
import com.promise.controller.Result;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义登录成功逻辑
 */
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException,
            ServletException {
        // todo：登录成功，返回token

        Result data = new Result(Code.CODE_SUCCESS, "登陆成功");

        // 设置返回消息类型
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json;charset=UTF-8");

        // 返回给前端
        response.getWriter().write(new ObjectMapper().writeValueAsString(data));
    }
}
