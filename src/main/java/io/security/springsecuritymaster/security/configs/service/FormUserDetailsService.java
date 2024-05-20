package io.security.springsecuritymaster.security.configs.service;

import io.security.springsecuritymaster.domain.dto.AccountContext;
import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userDetailsService") // 스프링 세팅파일에 설정하기 위해 이름을 통일시켜야 한다.
@RequiredArgsConstructor
public class FormUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if (account == null) { // 인증 실패 !
            throw new UsernameNotFoundException("No user found with username : " + username);
        }

        // 권한목록 가져오기
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRoles()));

        // Account 는 Entity 기 때문에 클라이언트 응답객체로 사용하지 않기 때문에 DTO로 수정
        ModelMapper mapper = new ModelMapper();
        AccountDto accountDto = mapper.map(account, AccountDto.class);

        // 사용자 정보를 갖고와서 반환(세션이 생성)
        return new AccountContext(accountDto, authorities);
    }
}
