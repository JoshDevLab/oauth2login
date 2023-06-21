package com.josh.oauth2login.domain.product.service;

import com.josh.oauth2login.domain.product.dto.ProductDTO;
import com.josh.oauth2login.domain.product.entity.Product;
import com.josh.oauth2login.domain.product.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;

    public Product registerProduct(ProductDTO productDTO) {
        Product product = productDTO.toEntity();
        return productRepository.save(product);
    }
}
