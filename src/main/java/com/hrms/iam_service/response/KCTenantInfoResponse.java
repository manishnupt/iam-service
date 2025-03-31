package com.hrms.iam_service.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Builder
public class KCTenantInfoResponse {

    private String id;
    private String realm;
    private String redirectURI;

}
