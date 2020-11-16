package com.kuang.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Wang Yue
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，但是功能页的访问需要权限
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        //没有权限默认会到登录页，开启登录页面，设置验证页
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/toLogin");

        //关闭 防止跨站攻击  否则会造成登出失败
        http.csrf().disable();
        //开启注销功能,设置注销成功要跳转的页面
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能   默认保存两周   自定义接收前端参数
        http.rememberMe().rememberMeParameter("remember");
    }

    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //正常应该从数据库中读取
        //密码需要加密
        //在Spring Security 5.0+ 新增了很多的加密方法
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("wangyue").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("wangyue3").password(new BCryptPasswordEncoder().encode("111")).roles("vip3");

    }
}
