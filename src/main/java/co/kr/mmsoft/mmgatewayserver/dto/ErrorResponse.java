package co.kr.mmsoft.mmgatewayserver.dto;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ErrorResponse {
    private String error;
    private String code;
    private String message;
}
