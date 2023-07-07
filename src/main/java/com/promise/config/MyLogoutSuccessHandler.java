package com.promise.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.promise.controller.Code;
import com.promise.controller.Result;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义注销逻辑
 */
@Component
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        // 设置返回值
        Result result = new Result(Code.CODE_FAIL, "注销成功");

        // 设置返回消息类型
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json;charset=UTF-8");

        // 返回给前端
        response.getWriter().write(new ObjectMapper().writeValueAsString(result));
    }
}
