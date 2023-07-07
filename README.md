# SpringSecurity-Discrete

## 项目简介

本项目采用 MySQL + Spring Security + Spring Boot + JWT进行开发，适用于**前后端分离**的项目来使用**Spring Security**进行身份和权限的校验。

主要实现了**注册（密码加密）**、自定义**未登录**逻辑、自定义**登录校验**逻辑、自定义**登录成功**逻辑、自定义**登陆失败**逻辑、自定义**注销**逻辑、自定义**多账户登录**、自定义**无权访问**逻辑、自定义**开启csrf保护**、**JWT**的认证刷新传递。

## 项目待开发功能

1. 添加JWT，实现登录成功后向客户端**传递token字符串**（已经完成）
2. **token认证**，在用户每次请求之前，解析请求头中的token，对用户的身份进行校验（已经完成）
3. **token刷新**，如果用户正在使用的时候，token过期了，则会直接跳转登录页，体验感极差。所以需要完善token刷新功能（已经完成）

## 项目文档

参考**help.md**文件，里面有详细的说明以及项目实现的效果

## 配置到自己的项目中

1. 克隆项目到本地

   ```bash
   git clone https://github.com/zhangb-top/SpringSecurity-Discrete.git
   ```

2. 参考help.md文档的 **前期准备** 部分，配置自己的开发环境和数据库

## 友情提示

如果对Spring Security不怎么熟悉的小伙伴可以参考[Spring Security的基本使用](http://www.zhangb.top/detail?id=43&title=Spring%20Security%E7%9A%84%E5%9F%BA%E6%9C%AC%E4%BD%BF%E7%94%A8)
