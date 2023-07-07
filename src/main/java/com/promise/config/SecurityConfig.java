package com.promise.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 自定义用户登录逻辑
    @Autowired
    private MyAuthenticationProvider authenticationProvider;

    // 自定义登录成功逻辑
    @Autowired
    private MyAuthenticationAccessHandler successHandler;

    // 自定义登录失败逻辑
    @Autowired
    private MyAuthenticationFailureHandler failureHandler;

    // 自定义无权访问逻辑
    @Autowired
    private MyAccessDeniedHandler accessDeniedHandler;

    // 自定义未登录逻辑
    @Autowired
    private MyAuthenticationEntryPoint entryPoint;

    // 自定义token验证过滤器
    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    // 自定义注销逻辑
    @Autowired
    private MyLogoutSuccessHandler logoutSuccessHandler;

    // 自定义多账户登录逻辑
    @Autowired
    private MySessionInformationExpiredStrategy sessionStrategy;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 配置自定义的用户登录逻辑
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 开启跨域
        http.cors().and().csrf().disable();

        http.authorizeRequests()
                // 登录、注册、刷新token接口不需要认证
                .antMatchers("/users/login", "/users/register", "/users/refreshToken").permitAll()
                // 跨域请求会先发出一个OPTIONS请求
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                // 除了上面的其他的都需要认证
                .anyRequest().authenticated()

                // 自定义登录
                .and()
                .formLogin()
                .loginProcessingUrl("/users/login")
                // 自定义登录成功逻辑
                .successHandler(successHandler)
                .failureHandler(failureHandler)

                // 自定义注销
                .and()
                .logout()
                .logoutUrl("/users/logout")
                .logoutSuccessHandler(logoutSuccessHandler)
                // 删除cookies
                .deleteCookies("JSESSIONID")

                .and()
                // 添加自定义的token验证过滤器
                .addFilterBefore(jwtAuthenticationTokenFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                // 自定义无权访问
                .accessDeniedHandler(accessDeniedHandler)
                // 自定义未登录
                .authenticationEntryPoint(entryPoint)

                // 自定义多账户登录
                .and()
                .sessionManagement()
                // 一个账号最多支持一个用户登录
                .maximumSessions(1)
                .expiredSessionStrategy(sessionStrategy);
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
