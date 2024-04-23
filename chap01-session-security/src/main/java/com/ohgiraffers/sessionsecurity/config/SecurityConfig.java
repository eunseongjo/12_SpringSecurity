package com.ohgiraffers.sessionsecurity.config;


import com.ohgiraffers.sessionsecurity.auth.model.AuthDetails;
import com.ohgiraffers.sessionsecurity.common.UserRole;
import com.ohgiraffers.sessionsecurity.config.handler.AuthFailHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AuthFailHandler authFailHandler;

    /* 비밀번호 암호화에 사용할 객체 BCryptPasswordEncoder bean 등록 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /* 정적 리소스에 대한 요청은 보안 제외하는 설정 */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        /* 요청에 대한 권한 체크 */
        http.authorizeHttpRequests( auth -> {
            auth.requestMatchers("/auth/login", "/user/signup", "/auth/fail", "/", "/main").permitAll(); //로그인 하지 않아도 페이지 보기 권한 허용
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole()); //admin 권한만 admin페이지 접근
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole()); //
            auth.anyRequest().authenticated();

        }).formLogin( login -> {
            login.loginPage("/auth/login");
            login.usernameParameter("user");
            login.passwordParameter("pass"); //password검사
            login.defaultSuccessUrl("/", true); //로그인 성공시 루트로 이동
            login.failureHandler(authFailHandler); //실패시

        }).logout( logout -> {
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout")); //logout에 매핑을 시키겠다.
            logout.deleteCookies("JSESSIONID"); //로그아웃 시 쿠키를 지운다
            logout.invalidateHttpSession(true); //소멸
            logout.logoutSuccessUrl("/"); //루트로 이동

        }).sessionManagement( session -> {
            session.maximumSessions(1); //세션 개수 1개
            session.invalidSessionUrl("/"); //만료시 루트로 이동

        }).csrf( csrf -> csrf.disable()); //csrf를 잠깐 풀어놓겠다.CSRF?보안

        return http.build();
    }
}