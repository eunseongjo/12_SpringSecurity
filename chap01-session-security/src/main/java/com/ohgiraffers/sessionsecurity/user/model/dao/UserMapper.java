package com.ohgiraffers.sessionsecurity.user.model.dao;

import com.ohgiraffers.sessionsecurity.user.model.dto.LoginUserDTO;
import com.ohgiraffers.sessionsecurity.user.model.dto.SignupDTO;
import org.apache.ibatis.annotations.Mapper;

@Mapper //MapperScan이 찾는 장소
public interface UserMapper {
    LoginUserDTO findByUsername(String username);

    int regist(SignupDTO signupDTO);
}
