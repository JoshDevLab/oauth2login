package com.josh.oauth2login.domain.product.controller;

import com.josh.oauth2login.domain.product.dto.ProductDTO;
import com.josh.oauth2login.domain.product.entity.Product;
import com.josh.oauth2login.domain.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/products")
public class ProductController {

    private final ProductService productService;

    @PostMapping
    public ResponseEntity<Product> registerProduct(@RequestBody ProductDTO productDTO) {
        return ResponseEntity.ok(productService.registerProduct(productDTO));
    }
}
