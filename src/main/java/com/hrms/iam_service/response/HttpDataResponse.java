package com.hrms.iam_service.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class HttpDataResponse {

    private int code;
    private String message;
    private Object data;
}
