package com.josh.oauth2login.domain.product.dto;

import com.josh.oauth2login.domain.product.entity.CategoryType;
import com.josh.oauth2login.domain.product.entity.Product;
import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Data
public class ProductDTO {

    @NotNull
    private String productName;

    @NotNull
    private Long quantity;

    @Enumerated(EnumType.STRING)
    @NotNull
    private CategoryType categoryType;

    public Product toEntity() {
        return Product.builder()
                .productName(productName)
                .quantity(quantity)
                .categoryType(categoryType)
                .build();
    }
}
