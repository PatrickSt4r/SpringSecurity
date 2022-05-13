package com.example.springsecurity.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//AOP : 拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权
    @Override//支持链式编程
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页只有对应有权限的人才能访问
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认会登录页面,需要开启登录的页面
        // .login
        //定制登陆页
        //自定义参数
        http.formLogin().loginPage("/toLogin").usernameParameter("usr").passwordParameter("pwd").loginProcessingUrl("/login");
        //关闭跨站攻击
        http.csrf().disable(); //登录失败可能的原因
        //注销,跳到首页
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能,自定义前端接收参数
        http.rememberMe().rememberMeParameter("remember");
    }

    //认证 springbott 2.1.x 可以直接使用
    //密码编码： PasswordEncoder
    //在Spring Security 5.0—— 新增很多了加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //数据正常应该从数据库中读取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("tian").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
