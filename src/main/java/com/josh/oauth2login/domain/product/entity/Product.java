package com.josh.oauth2login.domain.product.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Slf4j
@Getter
@Builder
@Entity
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long productSeq;

    @Column(name = "PRODUCT_NAME")
    @NotNull
    private String productName;

    @Column(name = "QUANTITY")
    @NotNull
    private Long quantity;

    @Column(name = "CATEGORY_TYPE")
    @Enumerated(EnumType.STRING)
    @NotNull
    private CategoryType categoryType;
}
