package com.example.demo.config;

import com.example.demo.jwt.JwtAccessDeniedHandler;
import com.example.demo.jwt.JwtAuthenticationEntryPoint;
import com.example.demo.jwt.JwtSecurityConfig;
import com.example.demo.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize을 메소드 단위로 사용하기 위함
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  private final TokenProvider tokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  public SecurityConfig(
          TokenProvider tokenProvider,
          JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
          JwtAccessDeniedHandler jwtAccessDeniedHandler) {
    this.tokenProvider = tokenProvider;
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring()
            .antMatchers(
                    "/h2-console/**",
                    "/favicon.ico"
            );
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // http.authorizeRequests() // HttpServletRequest 요청에 대해 제한 설정을 하겠다
    //         .antMatchers("/api/hello").permitAll() // 인증 없이 허용
    //         .anyRequest().authenticated(); // 인증 필요

    http
            .csrf().disable()

            .exceptionHandling()
            .authenticationEntryPoint(jwtAuthenticationEntryPoint)
            .accessDeniedHandler(jwtAccessDeniedHandler)

            // h2 콘솔 설정
            .and()
            .headers()
            .frameOptions()
            .sameOrigin()

            // 세션 설정 STATELESS
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            .and()
            .authorizeRequests()
            .antMatchers("/api/hello*").permitAll()
            .antMatchers("/api/authenticate").permitAll()
            .antMatchers("/api/signup").permitAll()

            .and()
            .apply(new JwtSecurityConfig(tokenProvider));
  }
}
