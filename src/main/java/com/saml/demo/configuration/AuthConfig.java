package com.saml.demo.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class AuthConfig extends WebSecurityConfigurerAdapter {

    /**
     * 重写该方法，设定用户访问权限
     * 用户身份可以访问 订单相关API
     * */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/orders/**").hasRole("USER")    //用户权限
//                .antMatchers("/users/**").hasRole("ADMIN")    //管理员权限
//                .antMatchers("/login").permitAll()
//                .and()
//                .formLogin();


        http.authorizeRequests()
                .antMatchers("/orders/**").hasRole("USER")    //用户权限
                .antMatchers("/users/**").hasRole("ADMIN")    //管理员权限
                .and()
                .formLogin()
                .loginPage("/login")    //跳转登录页面的控制器，该地址要保证和表单提交的地址一致！
                .permitAll()
                .and()
                .logout()
                .permitAll()
                .and()
                .csrf().disable();        //暂时禁用CSRF，否则无法提交表单
    }

    /**
     * 重写该方法，添加自定义用户
     * */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(new MyPasswordEncoder())
                .withUser("admin").password("admin").roles("ADMIN","USER")
                .and()
                .withUser("terry").password("terry").roles("USER")
                .and()
                .withUser("larry").password("larry").roles("USER");
    }

}
