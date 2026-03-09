package co.kr.mmsoft.mmgatewayserver.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Slf4j
@Component
public class JwtTokenProvider {
    private final SecretKey secretKey;

    public JwtTokenProvider(@Value("${app.jwt.secret}") String secret){
        if(secret ==null || secret.isBlank()){
            throw new IllegalStateException("app.jwt.secret 가 비어있네요, 환경변수 확인하세요");
        }
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }
    /*-----------------------------------
        검증 메서드 (게이트웨이 전용)+검증오류시 예외 발생
    -----------------------------------*/
    public void validateTokenOrThrow(String token){
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token);
        Claims claims=jws.getPayload();
        String subject=claims.getSubject();
        if(subject==null || subject.isBlank()){
            //토큰의 주인 정보가 빠져 있으므로, 이것 또한 유효하지 않은 토큰 범주로 넣을 수 있음
            throw new MalformedJwtException("Jwt 주인 정보가 없네요");
        }
    }
    /*-----------------------------------
        검증 메서드 (게이트웨이 전용)+검증오류시 논리값 발생
    -----------------------------------*/
    public boolean validateToken(String token){
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e){
            return false;
        }
    }

    /*-----------------------------------
        PayLoad 추출
    -----------------------------------*/
    public Claims getClaims(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /*-----------------------------------
    subject 추출
    -----------------------------------*/
    public String getSubject(String token) {
        return getClaims(token).getSubject();
    }
}
