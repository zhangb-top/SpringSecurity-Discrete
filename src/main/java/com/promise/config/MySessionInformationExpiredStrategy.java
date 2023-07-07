package com.promise.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.promise.controller.Code;
import com.promise.controller.Result;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义多账号登录逻辑
 */
@Component
public class MySessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException,
            ServletException {
        HttpServletResponse response = event.getResponse();
        // 设置返回值
        Result result = new Result(Code.CODE_FAIL, "多账户登录");

        // 设置返回消息类型
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json;charset=UTF-8");

        // 返回给前端
        response.getWriter().write(new ObjectMapper().writeValueAsString(result));
    }
}
