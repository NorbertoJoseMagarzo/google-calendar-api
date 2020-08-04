package com.api.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class APIController {

	@RequestMapping(value = "/products")
	   public String getProductName() {
	      return "Honey";   
	   }
}
