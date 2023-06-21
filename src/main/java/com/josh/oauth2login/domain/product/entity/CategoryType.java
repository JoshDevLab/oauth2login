package com.josh.oauth2login.domain.product.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum CategoryType {

    TOP("TOP", "상의"),
    PANTS("PANTS", "하의"),
    SHOES("SHOES", "신발");
    private String code;
    private String detail;


}
