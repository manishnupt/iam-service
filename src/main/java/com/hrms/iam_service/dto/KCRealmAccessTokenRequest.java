package com.hrms.iam_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KCRealmAccessTokenRequest {

    @NotBlank
    private String tenantName;
    @NotBlank
    private String authCode;
}
