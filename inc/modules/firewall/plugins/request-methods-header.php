<?php
/*
Module Name: Block Bad Request Methods
Description: Block requests methods spotted as potentially dangerous
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! defined( 'DOING_CRON' ) ) {

	// Block Bad request methods.
	$basic_methods = array( 'GET' => true, 'POST' => true, 'HEAD' => true );
	$rest_methods  = array( 'PUT' => true, 'PATCH' => true, 'DELETE' => true );
	$methods       = secupress_is_submodule_active( 'sensitive-data', 'restapi' ) ? array_merge( $basic_methods, $rest_methods ) : $basic_methods;

	if ( ! isset( $methods[ $_SERVER['REQUEST_METHOD'] ] ) ) {
		secupress_block( 'RMHM', 405 );
	}

}