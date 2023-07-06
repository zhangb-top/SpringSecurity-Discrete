package com.promise.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 自定义用户登录逻辑
    @Autowired
    private MyAuthenticationProvider authenticationProvider;

    // 自定义登录成功逻辑
    @Autowired
    private MyAuthenticationSuccessHandler successHandler;

    // 自定义登录失败逻辑
    @Autowired
    private MyAuthenticationFailureHandler failureHandler;

    // 自定义无权访问逻辑
    @Autowired
    private MyAccessDeniedHandler accessDeniedHandler;

    // 自定义未登录逻辑
    @Autowired
    private MyAuthenticationEntryPoint entryPoint;

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
                // 登录和注册接口不需要认证
                .antMatchers("/users/login", "/users/register").permitAll()
                // 除了上面的其他的都需要认证
                .anyRequest().authenticated()

                .and()
                .formLogin()
                .loginProcessingUrl("/users/login")
                // 自定义登录成功逻辑
                .successHandler(successHandler)
                .failureHandler(failureHandler)

                .and()
                .exceptionHandling()
                // 自定义无权访问
                .accessDeniedHandler(accessDeniedHandler)
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
