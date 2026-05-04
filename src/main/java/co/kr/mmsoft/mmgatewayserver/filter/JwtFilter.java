package co.kr.mmsoft.mmgatewayserver.filter;

import co.kr.mmsoft.mmgatewayserver.dto.ErrorResponse;
import co.kr.mmsoft.mmgatewayserver.jwt.JwtTokenProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements GlobalFilter, Ordered {

    private final ObjectMapper objectMapper;
    private final JwtTokenProvider jwtTokenProvider;
    /*------------------------------------
    Public API를 요청할 경우, 게이트웨이는 관여하면 안된다.. 즉 그냥 통과시켜야할 명단
    ------------------------------------*/
    private static final List<String>  PUBLIC_PREFIX=List.of(
            "/api/auth/idcheck",
            "/api/auth/regist",
            "/api/auth/login",
            "/api/auth/admin/login",
            "/api/auth/refresh",
            "/api/auth/idpassfind",
            "/api/auth/oauth2",  // OAuth2 임시코드 교환 (토큰 없이 호출)
            "/api/workboard",    // 워크보드 목록 (비로그인 공개)
            "/api/freeboard",    // 커뮤니티 게시판 (비로그인 조회 허용)
            "/swagger-ui",
            "/api/pds",
            "/images/pds",      // 제품소개 썸네일 이미지 (비로그인 공개)
            "/swagger-ui.html",
            "/oauth2",          // OAuth2 인증 시작 경로 (구글 로그인 등)
            "/login/oauth2",    // OAuth2 Callback(Redirect URI) 경로
            "/actuator",        // 헬스 체크
            "/api/payment/",    // 결제 콜백 - JWT 없이 KSPay/PC앱에서 호출
            "/api/auth/nice",   // NICE 본인인증 콜백 - JWT 없이 NICE 서버에서 호출
            "/api/auth/contact", // 광고페이지 문의 폼 - 비로그인 공개
            "/api/noim/sender/upload-doc",
            "/api/noim/sender/register",
            "/api/noim/sender/my",
            "/api/noim/sender/info",
            "/api/noim/sender/resend-key",
            "/api/noim/sms/send",
            "/api/noim/sms/balance-by-key",
            "/api/noim/sms/card-charge",
            "/api/noim/kakao/send",
            "/api/noim/kakao/templates",
            "/api/noim/access-log"
    );
    private boolean isPublicPath(String path){
        return PUBLIC_PREFIX.stream().anyMatch(path::startsWith);
    }
    @Override
    public int getOrder() {
        return -1; //반환값이 작을 수록 우선순위가 높다
    }
    /*------------------------------------
    인증되지 않은 경우의 처리 공통 메서드
    ------------------------------------*/
    private Mono<Void> writeJson(ServerWebExchange exchange, ErrorResponse errorBody){
        //게이트웨이 문자열 응답정보를 보내기 위해서는 코드가 상당히 복잡(저수준의 코드를 건드려야 함)
        try{
            byte[] bytes=objectMapper.writeValueAsBytes(errorBody);
            DataBuffer buffer =exchange.getResponse().bufferFactory().wrap((bytes));

            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e){
            //변환작업, 즉 JSON으로의 직렬화에 실패한 경우
            log.debug("json 변환 실패");

            return exchange.getResponse().setComplete(); //setComplete()이란? 게이트웨이 이후로 즉 다운스트림으로
            //이 요청의 흐름을 보내지 않으며 요청흐름은 여기서 종료
        }
    }
    /*------------------------------------
    인증되지 않은 경우의 처리 공통 메서드
    ------------------------------------*/
    private Mono<Void> unauthorized(ServerWebExchange exchange, String code, String message){
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        log.debug("게이트웨이에서 거절 처리함 code={}, message={}",code,message );
        return writeJson(exchange, new ErrorResponse("unauthrized", code, message));
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.debug("필터동작");
        /*-------------------------------------------------------
        prerflight(사전요청)은 무조건 통과
        -------------------------------------------------------*/
        if(exchange.getRequest().getMethod()== HttpMethod.OPTIONS){
            return chain.filter(exchange);
        }
        /*-------------------------------------------------------
        로그인 요청, 로그아웃 요청, 기타 token이 필요 없는 요청들에 대해서는 요청의 흐름을 다운스트림으로 전환
        -------------------------------------------------------*/
        String path = exchange.getRequest().getURI().getPath();
        log.debug("Current Request Path: {}", path);
        if(isPublicPath(path)){
            return chain.filter(exchange);
        }


        /*
        요청 헤서에서 Authorization 값을 꺼내기
        */
        String authHeader=exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.debug("게이트웨에서 꺼낸 header값은 {}", authHeader);

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return unauthorized(exchange, "missing_token", "Authorization 헤더가 없거나 Bearer 토큰이 아님");
        }

        String token = authHeader.substring(7).trim();

        log.debug("추출된 토큰은 {}", token);

        try {
            // [수정 포인트] 토큰 검증 시 발생하는 예외를 잡아서 401 응답으로 변환
            jwtTokenProvider.validateTokenOrThrow(token);
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.debug("토큰 만료: {}", e.getMessage());
            return unauthorized(exchange, "expired_token", "토큰이 만료되었습니다.");
        } catch (Exception e) {
            log.debug("토큰 검증 실패: {}", e.getMessage());
            return unauthorized(exchange, "invalid_token", "유효하지 않은 토큰입니다.");
        }
        //하위 스트림을 위해 필요한 정보를 추출하여 가공하여 전달하자
        //우리의 경우 accountId, Role(주의할점-member-service에서도 가능은 하지만, 업무효율상
        //게이트웨이에서 처리함
        Claims claims = jwtTokenProvider.getClaims(token);

        String accountId=jwtTokenProvider.getSubject(token);

        List<String> rolesList=claims.get("roles", List.class);

        String roles;
        if (rolesList != null) {
            roles = String.join(",", rolesList);
        } else {
            // admin 토큰은 "role" 단수 클레임 사용
            String singleRole = claims.get("role", String.class);
            roles = singleRole != null ? singleRole : "";
        }

        //현재의 요청 헤더에 원하는 값 심기
        ServerWebExchange mutatedExchange = exchange.mutate().request(req->req.headers(headers->{
            headers.set("X-AccountId", accountId); //MSA용
            headers.set("X-Roles", roles); //MSA용 커스텀 헤더 추가
        })).build();
        return chain.filter(mutatedExchange);
    }

}
