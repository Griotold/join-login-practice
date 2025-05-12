package com.griotold.join_login.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.ErrorResponse;

import java.io.IOException;

@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        // 요청 속성에서 예외 유형 확인
        Object exceptionType = request.getAttribute("exception");

        if (exceptionType != null) {
            log.error("Exception in filter: {}", exceptionType);
            handleException(response, exceptionType.toString());
        } else {
            handleException(response, "UNAUTHORIZED");
        }
    }

    private void handleException(HttpServletResponse response, String errorType){
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            int statusCode = HttpServletResponse.SC_UNAUTHORIZED; // 기본 상태 코드 설정
            String message = "Unauthorized access";

            switch (errorType) {
                case "NOT_TOKEN":
                    statusCode = HttpServletResponse.SC_BAD_REQUEST;
                    message = "Token is missing";
                    break;
                case "NOT_VALID_TOKEN":
                    statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                    message = "Token is invalid";
                    break;
                case "NOT_FOUND_USER":
                    statusCode = HttpServletResponse.SC_FORBIDDEN;
                    message = "User not found";
                    break;
                default:
                    break;
            }

            response.setStatus(statusCode);
//            String json = new ObjectMapper().writeValueAsString(new ErrorResponse(statusCode, message));
            String json = "";
            response.getWriter().write(json);
        } catch (IOException e) {
            log.error("Failed to write error response: {}", e.getMessage());
        }
    }

}
