package com.promise.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    // id
    private Integer id;
    // 用户名
    private String username;
    // 密码
    private String password;
    // 角色
    private String role;
    // 权限
    private String permissions;
}
