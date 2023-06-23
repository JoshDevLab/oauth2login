package com.josh.oauth2login;

import com.josh.oauth2login.domain.product.dto.ProductDTO;
import com.josh.oauth2login.domain.product.entity.CategoryType;
import com.josh.oauth2login.domain.product.entity.Product;
import com.josh.oauth2login.domain.product.service.ProductService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class ProductTest {

    @Autowired
    private ProductService productService;

    @Test
    public void registerProductTest() {
        //given
        ProductDTO product = ProductDTO.builder()
                .productName("test1")
                .quantity(1000L)
                .categoryType(CategoryType.PANTS)
                .build();

        //when
        Product product1 = productService.registerProduct(product);

        //then
        Assertions.assertThat(product1.getProductName()).isEqualTo("test1");
    }
}
