package co.kr.mmsoft.mmgatewayserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Spring Cloud Gateway - Security 설정
 *
 * 문제: Spring Security 기본 설정이 CSRF를 활성화함
 *   → 브라우저는 모든 요청에 Origin 헤더를 포함
 *   → CSRF 필터가 Origin 헤더를 감지하고 CSRF 토큰 없는 POST를 403으로 차단
 *   → curl (Origin 헤더 없음)은 통과, 브라우저는 차단되는 현상 발생
 *
 * 해결: CSRF 비활성화 (REST API 게이트웨이에서는 불필요)
 *   - 인증은 JwtFilter (GlobalFilter) 에서 처리
 *   - Spring Security는 CSRF/CORS 설정만 담당
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll()   // 인증은 JwtFilter(GlobalFilter)에서 처리
                )
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
