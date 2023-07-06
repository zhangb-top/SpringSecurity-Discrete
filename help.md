# Spring Security的前后端分离配置

## 1、前期准备

本次项目采用Mysql + Mybatis Plus + Spring Boot + Spring Security进行开发

1. 创建数据库表格

   ```sql
   CREATE TABLE tb_user(
   	id INT PRIMARY KEY AUTO_INCREMENT,
   	username VARCHAR(60) NOT NULL,
   	password VARCHAR(255) NOT NULL,
   	-- 默认用户角色
   	role VARCHAR(20) NOT NULL DEFAULT 'ROLE_user',
   	-- 默认只有观看权限
   	permissions VARCHAR(20) NOT NULL DEFAULT 'watch'
   );
   ```

2. 引入依赖

   ```xml
   <dependencies>
       <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-security</artifactId>
       </dependency>
   
       <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-web</artifactId>
       </dependency>
   
       <dependency>
           <groupId>com.mysql</groupId>
           <artifactId>mysql-connector-j</artifactId>
           <scope>runtime</scope>
       </dependency>
   
       <dependency>
           <groupId>org.projectlombok</groupId>
           <artifactId>lombok</artifactId>
           <optional>true</optional>
       </dependency>
   
       <dependency>
           <groupId>com.baomidou</groupId>
           <artifactId>mybatis-plus-boot-starter</artifactId>
           <version>3.5.3.1</version>
       </dependency>
   </dependencies>
   ```

3. 配置数据库信息

   ```yml
   spring:
     datasource:
       driver-class-name: com.mysql.cj.jdbc.Driver
       url: jdbc:mysql:///db1?useSSL=false&serverTimezone=GMT%2B8
       username: root
       password: 666666
   
   mybatis-plus:
     global-config:
       db-config:
         # 由于我的数据库表格以tb_开头，如果没有表前缀则可以忽略
         table-prefix: tb_
         id-type: auto
   ```

4. 建立实体类User

   ```java
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
   ```

5. 配置Mybatis Plus的dao层和server层

   ```java
   @Mapper
   public interface UserDao extends BaseMapper<User> {
   }
   ```

   ```java
   public interface UserService extends IService<User> {
   }
   ```

   ```java
   @Service
   public class UserServiceImpl extends ServiceImpl<UserDao, User> implements UserService,
           UserDetailsService {
   
       @Autowired
       private UserDao userDao;
   
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
           // 后面完善
       }
   }
   ```

6. 设置统一格式的返回值

   ```java
   @Data
   @AllArgsConstructor
   public class Result {
       private Integer code;
       private String message;
       private Map<String, Object> data = new HashMap<>();
   
       public Result(Integer code, String message) {
           this.code = code;
           this.message = message;
       }
   }
   ```

   ```java
   public final class Code {
       public static Integer CODE_SUCCESS = 200;
       public static Integer CODE_FAIL = 500;
       public static Integer CODE_NOTFOUND = 403;
       // 可以继续自定义添加......
   
       private Code() {
       }
   }
   ```

## 2、配置登录与注册

1. 完善`UserServiceImpl`类中的`loadUserByUsername`方法，在里面查询数据库

   ```java
   @Override
   public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       QueryWrapper<User> wrapper = new QueryWrapper<>();
       wrapper.eq("username", username);
       User user = userDao.selectOne(wrapper);
       if (user == null) throw new UsernameNotFoundException("用户不存在");
   
       // 获取用户身份和权限
       List<GrantedAuthority> grantedAuthorities =
           AuthorityUtils.commaSeparatedStringToAuthorityList(user.getRole() + "," + user.getPermissions());
       return new org.springframework.security.core.userdetails.User(username,
                                                                     user.getPassword(), grantedAuthorities);
   }
   ```

2. `MyAuthenticationEntryPoint`：实现`AuthenticationEntryPoint`接口，自定义未登录的逻辑，这样就可以不必进入默认的登陆页面，直接返回JSON数据即可

   ```java
   /**
    * 自定义未登录逻辑
    */
   @Component
   public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
       @Override
       public void commence(HttpServletRequest request, HttpServletResponse response,
                            AuthenticationException authException) 
           throws IOException, ServletException {
           Result data = new Result(Code.CODE_FAIL, "未登录");
   
           // 设置返回消息类型
           response.setHeader("Content-type", "text/html;charset=UTF-8");
           response.setCharacterEncoding("utf-8");
           response.setContentType("application/json;charset=UTF-8");
   
           // 返回给前端
           response.getWriter().write(new ObjectMapper().writeValueAsString(data));
       }
   }
   ```

3. `MyAuthenticationProvider`：实现`AuthenticationProvider`接口，重新自定义校验逻辑

   ```java
   /**
    * 自定义校验逻辑
    */
   @Component
   public class MyAuthenticationProvider implements AuthenticationProvider {
   
       @Autowired
       private UserServiceImpl userService;
   
       @Override
       public Authentication authenticate(Authentication authentication) 
           throws AuthenticationException {
           // 获取用户名
           String username = authentication.getName();
           // 获取密码
           String password = (String) authentication.getCredentials();
           UserDetails userDetails = userService.loadUserByUsername(username);
   
           // todo：对前端密码进行解密，保存在password中
   		
           // 这里为什么不采用注入的BCryptPasswordEncoder对象？
           // 如果使用注入的BCryptPasswordEncoder对象，并且该对象配置在SercurityConfig类中，会产生循环依赖
           boolean flag = new BCryptPasswordEncoder().matches(password, userDetails.getPassword());
           if (!flag) throw new BadCredentialsException("密码错误");
   
           return new 
               UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
       }
   
       @Override
       public boolean supports(Class<?> authentication) {
           return true;
       }
   }
   ```

4. `MyAuthenticationSuccessHandler`：实现`AuthenticationSuccessHandler`接口，自定义登录成功的逻辑

   ```java
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
   ```

5. `MyAuthenticationFailureHandler`：实现`AuthenticationFailureHandler`接口，自定义登录失败的逻辑

   ```java
   /**
    * 自定义登录失败的逻辑
    */
   @Component
   public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
   
       @Override
       public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException exception) throws IOException,
               ServletException {
           // 设置返回消息
           Result data = new Result(Code.CODE_FAIL, exception.getMessage());
   
           // 设置返回消息类型
           response.setHeader("Content-type", "text/html;charset=UTF-8");
           response.setCharacterEncoding("utf-8");
           response.setContentType("application/json;charset=UTF-8");
   
           // 返回给前端
           response.getWriter().write(new ObjectMapper().writeValueAsString(data));
       }
   }
   ```

6. `SecurityConfig`：Spring Security的配置类，继承`WebSecurityConfigurerAdapter`

   ```java
   @Configuration
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
       
       // 自定义未登录逻辑
       @Autowired
       private MyAuthenticationEntryPoint entryPoint;
   
       // 自定义用户登录逻辑
       @Autowired
       private MyAuthenticationProvider authenticationProvider;
   
       // 自定义登录成功逻辑
       @Autowired
       private MyAuthenticationSuccessHandler successHandler;
   
       // 自定义登录失败逻辑
       @Autowired
       private MyAuthenticationFailureHandler failureHandler;
   
       @Override
       protected void configure(AuthenticationManagerBuilder auth) throws Exception {
           // 配置自定义的用户登录逻辑
           auth.authenticationProvider(authenticationProvider);
       }
   
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           // 开启跨域 关闭csrf保护（与rest风格冲突）
           http.cors().and().csrf().disable();
   
           http.authorizeRequests()
                   // 登录和注册接口不需要认证
                   .antMatchers("/users/login", "/users/register").permitAll()
                   // 除了上面的其他的都需要认证
                   .anyRequest().authenticated()
   
                   .and()
                   .formLogin()
               	// 这里的接口无需在UserController类中编写，Spring Security已经配置完成，只需要起一个名字
                   .loginProcessingUrl("/users/login")
                   // 自定义登录成功逻辑
                   .successHandler(successHandler)
               	// 自定义登录失败逻辑
                   .failureHandler(failureHandler)
   
                   .and()
                   .exceptionHandling()
                   // 自定义未登录
                   .authenticationEntryPoint(entryPoint);
       }
   
       /**
        * 配置加密算法
        *
        * @return BCryptPasswordEncoder
        */
       @Bean
       public BCryptPasswordEncoder passwordEncoder() {
           return new BCryptPasswordEncoder();
       }
   }
   ```

7. 注册接口

   ```java
   @RequestMapping("/users")
   @RestController
   public class UserController {
   
       @Autowired
       private BCryptPasswordEncoder passwordEncoder;
   
       @Autowired
       private UserServiceImpl userService;
   
       @PostMapping("/register")
       @ResponseBody
       public Result register(@RequestBody User user) {
           // 判断用户名是否重复
           QueryWrapper<User> wrapper = new QueryWrapper<>();
           wrapper.eq("username", user.getUsername());
           User selectUser = userService.getOne(wrapper);
           if (selectUser != null) return new Result(Code.CODE_FAIL, "用户名被占用");
   
           // 密码加密
           user.setPassword(passwordEncoder.encode(user.getPassword()));
           boolean flag = userService.save(user);
           Integer code = flag ? Code.CODE_SUCCESS : Code.CODE_FAIL;
           String message = flag ? "注册成功" : "注册失败";
           return new Result(code, message);
       }
   }
   ```

8. postman进行测试

   - 注册成功

     <img src="http://cdn.zhangb.top/register.jpg" alt="register" style="zoom:50%;" />

     ![user_table_1](http://cdn.zhangb.top/user_table_1.jpg)

   - 注册失败

     <img src="http://cdn.zhangb.top/register_error.jpg" alt="register_error" style="zoom:50%;" />

   - 登录成功

     <img src="http://cdn.zhangb.top/login.jpg" alt="login" style="zoom:50%;" />

   - 用户名错误

     <img src="http://cdn.zhangb.top/username_error.jpg" alt="username_error" style="zoom:50%;" />

   - 密码错误

     <img src="http://cdn.zhangb.top/password_error.jpg" alt="password_error" style="zoom:50%;" />

## 3、配置无权访问

1. `MyAccessDeniedHandler`：实现Spring Security中的`AccessDeniedHandler`接口，自定义无权访问逻辑

   ```java
   /**
    * 自定义无权访问
    */
   @Component
   public class MyAccessDeniedHandler implements AccessDeniedHandler {
       @Override
       public void handle(HttpServletRequest request, HttpServletResponse response,
                          AccessDeniedException accessDeniedException) throws IOException,
               ServletException {
           Result data = new Result(Code.CODE_NOTFOUND, "无权访问");
   
           // 设置返回消息类型
           response.setHeader("Content-type", "text/html;charset=UTF-8");
           response.setCharacterEncoding("utf-8");
           response.setContentType("application/json;charset=UTF-8");
   
           // 返回给前端
           response.getWriter().write(new ObjectMapper().writeValueAsString(data));
       }
   }
   ```

2. 在Security配置类中注入MyAccessDeniedHandler对象，同时在configure(HttpSecurity http)方法中，添加**异常处理（exceptionHadnling）**中的**无权访问处理（accessDeniedHandler）**

   ```java
   @Autowired
   private MyAccessDeniedHandler accessDeniedHandler;
   
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       
       // 省略......
       
       http.exceptionHandling()
           // 设置无权访问处理
           .accessDeniedHandler(accessDeniedHandler);
   }
   ```

3. SpringBoot启动类上配置@EnableGlobalMethodSecurity(prePostEnabled = true)

   ```java
   @SpringBootApplication
   @EnableGlobalMethodSecurity(prePostEnabled = true)
   public class Application {
   
       public static void main(String[] args) {
           SpringApplication.run(Application.class, args);
       }
   
   }
   ```

4. 测试接口

   ```java
   @RequestMapping("/users")
   @RestController
   public class UserController {
       @GetMapping("/test")
       // 只有管理员才可以访问
       @PreAuthorize("hasRole('admin')")
       @ResponseBody
       public Result test() {
           return new Result(Code.CODE_SUCCESS, "test");
       }
   }
   ```

5. postman测试

   <img src="http://cdn.zhangb.top/nofound.jpg" alt="nofound" style="zoom:50%;" />

## 4、开启csrf保护（REST风格不可开启）

> 什么是csrf
>
>
> CSRF（Cross-Site Request Forgery），中文翻译为跨站请求伪造，是一种常见的网络安全攻击方式。它利用了Web应用程序中的漏洞，通过伪装合法用户的请求，使用户在不知情的情况下执行了恶意操作。
>
> 攻击者通常会构造一个包含恶意代码的请求，然后诱使受害者在另一个网站上点击了一个看似无害的链接。当受害者登录到目标网站时，他们的浏览器会自动发送之前构造的恶意请求到<font color=red>用户浏览器打开并且认证过的其他网站</font>，而受害者并不知情。由于目标网站无法区分合法请求和攻击者构造的请求，所以它会处理该请求并执行对应的操作，导致攻击成功。

开启csrf保护，Spring Security会针对patch、put、post、delete请求进行保护

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	// 开启前后端分离式的csrf保护
    http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
}
```

![QQ截图20230705203622](http://cdn.zhangb.top/QQ截图20230705203622.jpg)
