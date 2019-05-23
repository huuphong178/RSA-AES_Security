package com.vng.hotelrest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

@Configuration
@EnableWebSecurity

//@EnableGlobalMethodSecurity(securedEnabled = true)
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource(name = "userService")
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(encoder());
    }

    @Bean
    public JwtAuthenticationFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationFilter();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().
                authorizeRequests()
                //Permit All
                .antMatchers("/rsa/*").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth","/api/auth/*").permitAll()
                .antMatchers(HttpMethod.GET,"/api/auth/*","/api/auth").permitAll()
                .antMatchers(HttpMethod.GET,"/api/nav_role","/api/nav_role/*").permitAll()
                .antMatchers("/token/*", "/signup").permitAll()
                //Role
                .antMatchers("/users").hasAnyRole("USER","CS","ADMIN")
                .antMatchers("/api/rooms","/api/room/*","/api/room").hasAnyRole("USER","CS","ADMIN")
                .antMatchers("/users").hasRole("ADMIN")
                .antMatchers("/api/auth","/api/auth/*").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,"/api/nav_role","/api/nav_role/*").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        http
                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        // Cấu hình concurrent session
        //  http.sessionManagement().sessionFixation().newSession()
            // url chuyen huong khi session het han
        //         .invalidSessionUrl("/login?message=timeout")
            // so session lon nhat co the hoat dong dong thoi
         //        .maximumSessions(1)t
            // chuyen huong khi dat maxsession
        //        .expiredUrl("/login?message=max_session")
            //true la ko the login noi khac khi max session
        //        .maxSessionsPreventsLogin(true);
    }

    @Bean
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

}
