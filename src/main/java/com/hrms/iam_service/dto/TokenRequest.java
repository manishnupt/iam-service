package com.hrms.iam_service.dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String refreshToken;
}
