package co.kr.mmsoft.mmgatewayserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Spring Cloud Gateway - Security / CORS 설정
 *
 * 문제 1: Spring Security 기본 CSRF 활성화
 *   → 브라우저 Origin 헤더 감지 시 CSRF 토큰 없는 POST → 403 차단
 *   → curl(Origin 없음)은 통과, 브라우저는 차단
 *
 * 문제 2: Spring Cloud Gateway 자체 CORS 검증("Invalid CORS request")
 *   → admin 사이트(mmsoft.co.kr:8576) 등 Origin이 허용 목록에 없으면 차단
 *
 * 해결:
 *   1. CSRF 비활성화 (REST API 게이트웨이 불필요)
 *   2. 최우선순위 CorsWebFilter로 Gateway CORS 검증보다 먼저 처리
 *   - 인증은 JwtFilter(GlobalFilter)에서 담당
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * 최우선 CORS 필터: Spring Cloud Gateway의 자체 CORS 검증보다 먼저 실행
     * allowedOriginPatterns("*")로 모든 오리진 허용 (admin 포트 등 포함)
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())           // CorsWebFilter가 직접 처리
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll()       // 인증은 JwtFilter(GlobalFilter)에서 처리
                )
                .build();
    }
}
