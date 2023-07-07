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
   
   <dependency>
       <groupId>io.jsonwebtoken</groupId>
       <artifactId>jjwt</artifactId>
       <version>0.9.1</version>
   </dependency>
   
   <dependency>
       <groupId>cn.hutool</groupId>
       <artifactId>hutool-all</artifactId>
       <version>5.5.8</version>
   </dependency>
   
   <dependency>
       <groupId>javax.xml.bind</groupId>
       <artifactId>jaxb-api</artifactId>
       <version>2.3.0</version>
   </dependency>
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
               	// 跨域请求会先发出一个OPTIONS请求
           		.antMatchers(HttpMethod.OPTIONS).permitAll()
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

## 4、配置注销

1. `MyLogoutSuccessHandler`：实现`LogoutSuccessHandler`接口，自定义注销的逻辑

   ```java
   **
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
   ```

2. 在`SecurityConfig`中进行配置

   ```java
   // 自定义注销逻辑
   @Autowired
   private MyLogoutSuccessHandler logoutSuccessHandler;
   
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()
           // 省略......
   
           // 自定义注销
           .and()
           .logout()
           .logoutUrl("/users/logout")
           .logoutSuccessHandler(logoutSuccessHandler)
           // 删除cookies
           .deleteCookies("JSESSIONID")
   }
   ```

3. postman测试

   <img src="http://cdn.zhangb.top/logout.jpg" alt="logout" style="zoom:50%;" />

## 5、配置多账号登录

1. `MySessionInformationExpiredStrategy`：实现`SessionInformationExpiredStrategy`接口，自定义多账户登录

   ```java
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
   ```

2. 在`SecurityConfig`中进行配置

   ```java
   // 自定义多账户登录逻辑
   @Autowired
   private MySessionInformationExpiredStrategy sessionStrategy;
   
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       // 开启跨域
       http.cors().and().csrf().disable();
   
       http.authorizeRequests()
           // 省略......
   
           // 自定义多账户登录
           .and()
           .sessionManagement()
           // 一个账号最多支持一个用户登录
           .maximumSessions(1)
           .expiredSessionStrategy(sessionStrategy);
   }
   ```

## 6、添加JWT完善登录流程

1. 在application.yml中配置jwt信息

   ```yml
   jwt:
     # token有效期1天
     expiration: 86400
     secret: promise
     # 请求头中token的前缀
     tokenHead: Bearer
     # token保存在请求头中的位置
     tokenHeader: Authorization
   ```

2. 新建utils包，在里面添加`JwtTokenUtil`工具类

   ```java
   @Component
   public class JwtTokenUtil {
       private static final String CLAIM_KEY_USERNAME = "promise";
       private static final String CLAIM_KEY_CREATED = "created";
       @Value("${jwt.secret}")
       private String secret;
       @Value("${jwt.expiration}")
       private Long expiration;
       @Value("${jwt.tokenHead}")
       private String tokenHead;
   
       /**
        * 根据负责生成JWT的token
        */
       private String generateToken(Map<String, Object> claims) {
           return Jwts.builder()
                   .setClaims(claims)
                   .setExpiration(generateExpirationDate())
                   .signWith(SignatureAlgorithm.HS512, secret)
                   .compact();
       }
   
       /**
        * 从token中获取JWT中的负载
        */
       private Claims getClaimsFromToken(String token) throws TokenException {
           Claims claims = null;
           try {
               claims = Jwts.parser()
                       .setSigningKey(secret)
                       .parseClaimsJws(token)
                       .getBody();
           } catch (Exception e) {
               throw new TokenException("token验证失败");
           }
           return claims;
       }
   
       /**
        * 生成token的过期时间
        */
       private Date generateExpirationDate() {
           return new Date(System.currentTimeMillis() + expiration * 1000);
       }
   
       /**
        * 从token中获取登录用户名
        */
       public String getUserNameFromToken(String token) {
           String username;
           try {
               Claims claims = getClaimsFromToken(token);
               username = claims.getSubject();
           } catch (Exception e) {
               username = null;
           }
           return username;
       }
   
       /**
        * 验证token是否还有效
        *
        * @param token       客户端传入的token
        * @param userDetails 从数据库中查询出来的用户信息
        */
       public boolean validateToken(String token, UserDetails userDetails) {
           String username = getUserNameFromToken(token);
           return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
       }
   
       /**
        * 判断token是否已经失效
        */
       private boolean isTokenExpired(String token) {
           Date expiredDate = getExpiredDateFromToken(token);
           return expiredDate.before(new Date());
       }
   
       /**
        * 从token中获取过期时间
        */
       private Date getExpiredDateFromToken(String token) {
           Claims claims = getClaimsFromToken(token);
           return claims.getExpiration();
       }
   
       /**
        * 根据用户信息生成token
        */
       public String generateToken(UserDetails userDetails) {
           Map<String, Object> claims = new HashMap<>();
           claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
           claims.put(CLAIM_KEY_CREATED, DateUtil.date());
           return generateToken(claims);
       }
   
       /**
        * 当原来的token没过期时是可以刷新的
        *
        * @param oldToken 带tokenHead的token
        */
       public String refreshHeadToken(String oldToken) {
           if (StrUtil.isEmpty(oldToken)) {
               return null;
           }
           String token = oldToken.substring(tokenHead.length());
           if (StrUtil.isEmpty(token)) {
               return null;
           }
           //token校验不通过
           Claims claims = getClaimsFromToken(token);
           if (Objects.isNull(claims)) {
               return null;
           }
           //如果token已经过期，不支持刷新
           if (isTokenExpired(token)) {
               return null;
           }
           //如果token在30分钟之内刚刷新过，返回原token
           if (tokenRefreshJustBefore(token, 30 * 60)) {
               return token;
           } else {
               claims.put(CLAIM_KEY_CREATED, new Date());
               return generateToken(claims);
           }
       }
   
       /**
        * 判断token在指定时间内是否刚刚刷新过
        *
        * @param token 原token
        * @param time  指定时间（秒）
        */
       private boolean tokenRefreshJustBefore(String token, int time) {
           Claims claims = getClaimsFromToken(token);
           Date created = claims.get(CLAIM_KEY_CREATED, Date.class);
           Date refreshDate = new Date();
           //刷新时间在创建时间的指定时间内
           return 
              refreshDate.after(created) && refreshDate.before(DateUtil.offsetSecond(created, time));
       }
   }
   ```

3. 新建token处理过滤器`JwtAuthenticationTokenFilter`，实现`OncePerRequestFilter`接口，校验请求头中的token字符串

   ```java
   /**
    * token处理过滤器
    */
   @Component
   public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
       @Autowired
       private UserServiceImpl userService;
       @Value("${jwt.tokenHeader}")
       private String tokenHeader;
       @Autowired
       private JwtTokenUtil jwtTokenUtil;
       @Value("${jwt.tokenHead}")
       private String tokenHead;
       
       @Override
       protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                       FilterChain filterChain) throws ServletException, IOException {
           String authHeader = request.getHeader(this.tokenHeader);
           if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
               String authToken = authHeader.substring(this.tokenHead.length());// "Bearer "
               String username = jwtTokenUtil.getUserNameFromToken(authToken);
               if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                   UserDetails userDetails = userService.loadUserByUsername(username);
                   if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                       UsernamePasswordAuthenticationToken authentication =
                               new UsernamePasswordAuthenticationToken(
                                       userDetails, null, userDetails.getAuthorities());
                       authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                       SecurityContextHolder.getContext().setAuthentication(authentication);
                   }
               }
           }
           filterChain.doFilter(request, response);
       }
   }
   ```

4. 在`SecurityConfig`配置类中添加token处理过滤器，把它放在`UsernamePasswordAuthenticationFilter`过滤器前面

   ```java
   / 自定义token验证过滤器
       @Autowired
       private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
   
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()
           // 省略......
   
           .and()
           // 添加自定义的token验证过滤器
           .addFilterBefore(jwtAuthenticationTokenFilter,
                            UsernamePasswordAuthenticationFilter.class)
           .exceptionHandling()
           // 自定义无权访问
           .accessDeniedHandler(accessDeniedHandler)
           // 自定义未登录
           .authenticationEntryPoint(entryPoint);
   }
   ```

5. 新建一个`TokenException`自定义异常类，用来接收与token有关的异常

   ```java
   public class TokenException extends RuntimeException {
       private String message;
   
       public TokenException(String message) {
           super(message);
           this.message = message;
       }
   
       @Override
       public String getMessage() {
           return message;
       }
   
       public void setMessage(String message) {
           this.message = message;
       }
   }
   ```

6. 修改`MyAuthenticationAccessHandler`类，要求登录成功后，向前端返回token字符串

   ```java
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
   ```

7. 在controller包下，新建一个`ProjectAdvice`类，用来统一处理系统会出现的异常

   ```java
   @RestControllerAdvice
   public class ProjectAdvice {
       @ExceptionHandler(TokenException.class)
       public Result doTokenException(TokenException e) {
           return new Result(Code.CODE_FAIL, e.getMessage());
       }
   }
   ```

8. postman测试

   <img src="http://cdn.zhangb.top/token.jpg" alt="token" style="zoom:50%;" />

## 7、添加Token刷新功能

1. 在`UserService`中添加刷新Token的函数，并且在`UserServiceImpl`中实现

   ```java
   public interface UserService extends IService<User> {
       String refreshToken(String oldToken);
   }
   ```

   ```java
   @Service
   public class UserServiceImpl extends ServiceImpl<UserDao, User> implements UserService,
           UserDetailsService {
       @Autowired
       private JwtTokenUtil jwtTokenUtil;
   
       @Override
       public String refreshToken(String oldToken) {
           return jwtTokenUtil.refreshHeadToken(oldToken);
       }
   }
   ```

2. 在`UserController`类中添加刷新Token的接口

   ```java
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
   ```

3. postman测试

   - 刷新token成功

     <img src="http://cdn.zhangb.top/refresh_token.jpg" alt="refresh_token" style="zoom:50%;" />

   - 刷新token失败

     <img src="http://cdn.zhangb.top/refersh_token_error.jpg" alt="refersh_token_error" style="zoom:50%;" />

   - token认证失败

     <img src="http://cdn.zhangb.top/token_authentication_error.jpg" alt="token_authentication_error" style="zoom:50%;" />

## 8、开启csrf保护（REST风格不可开启）

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
