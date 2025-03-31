package com.hrms.iam_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class KCValidateTenantRequest {

    @NotBlank
    private String tenantName;
}
