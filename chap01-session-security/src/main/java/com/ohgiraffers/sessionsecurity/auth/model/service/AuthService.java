package com.ohgiraffers.sessionsecurity.auth.model.service;

import com.ohgiraffers.sessionsecurity.auth.model.AuthDetails;
import com.ohgiraffers.sessionsecurity.user.model.dto.LoginUserDTO;
import com.ohgiraffers.sessionsecurity.user.model.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/*security에서 사용자의 아이디를 인증하기 위한 interface이다.
* loadUserByUsername을 필수로 구현해야 되며 로그인 인증시 해당 매서드에
* login 요청 시 전달 된 사용자의 id를 매개변수로 DB에서 조회한다. */
@Service
public class AuthService implements UserDetailsService {


    @Autowired
    private UserService userService;


    /* AuthenticationProvider에서 호출하는 메소드로,
    * login 요청 시 전달 된 사용자의 id 를 매개변수로 DB에서 사용자의 정보를 찾는다.
    * 전달된 사용자의 개체 타입은 UserDetails를 구현한 구현체가 되어야 한다.*/
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        LoginUserDTO login = userService.findByUsername(username);

        if(Objects.isNull(login)) {
            throw new UsernameNotFoundException("해당하는 회원 정보가 존재하지 않습니다.");
        }

        return new AuthDetails(login);
    }
}
