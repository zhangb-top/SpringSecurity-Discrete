package com.promise.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.promise.pojo.User;
import com.promise.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RequestMapping("/users")
@RestController
public class UserController {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private UserServiceImpl userService;

    @Value("${jwt.tokenHeader}")
    private String tokenHeader;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @GetMapping("/test")
    @PreAuthorize("hasRole('admin')")
    @ResponseBody
    public Result test() {
        return new Result(Code.CODE_SUCCESS, "test");
    }

    @PostMapping("/register")
    @ResponseBody
    public Result register(@RequestBody User user) {
        // 判断用户名是否重复
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("username", user.getUsername());
        User selectUser = userService.getOne(wrapper);
        if (selectUser != null) return new Result(Code.CODE_FAIL, "用户名被占用");

        // 密码加密
        System.out.println(passwordEncoder);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        boolean flag = userService.save(user);
        Integer code = flag ? Code.CODE_SUCCESS : Code.CODE_FAIL;
        String message = flag ? "注册成功" : "注册失败";
        return new Result(code, message);
    }

    @PostMapping("/refreshToken")
    @ResponseBody
    public Result refreshToken(HttpServletRequest request) {
        String token = request.getHeader(tokenHeader);
        String refreshToken = userService.refreshToken(token);
        Integer code = StrUtil.isEmpty(refreshToken) ? Code.CODE_FAIL : Code.CODE_SUCCESS;
        String message = StrUtil.isEmpty(refreshToken) ? "刷新token失败" : "刷新token成功";
        Map<String, Object> data = new HashMap<>();
        data.put("token", refreshToken);
        data.put("tokenHead", tokenHead);
        return new Result(code, message, data);
    }
}
