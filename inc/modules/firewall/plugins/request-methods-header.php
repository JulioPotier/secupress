<?php
/*
Module Name: Block Bad Request Methods
Description: Block requests methods spotted as potentially dangerous
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! defined( 'DOING_CRON' ) ) :

// Block Bad request methods
$basic_methods = array( 'GET' => true, 'POST' => true, 'HEAD' => true );
$rest_methods  = array( 'PUT' => true, 'PATCH' => true, 'DELETE' => true );
$methods       = secupress_is_submodule_active( 'sensitive-data', 'restapi' ) ? array_merge( $basic_methods, $rest_methods ) : $basic_methods;

if ( ! isset( $methods[ $_SERVER['REQUEST_METHOD'] ] ) ) {
	secupress_block( 'RMHM', 405 );
}

// Block Bad protocol method
if ( 'POST' === $_SERVER['REQUEST_METHOD'] && ! isset( $_SERVER['HTTP_HOST'] ) && ( ! isset( $_SERVER['SERVER_PROTOCOL'] ) || 'HTTP/1.0' === $_SERVER['SERVER_PROTOCOL'] ) ) {
	secupress_block( 'RMHP', 505 );
}


// Block Bad post with referer request
if ( 'POST' === $_SERVER['REQUEST_METHOD'] && ( ! isset( $_SERVER['HTTP_REFERER'] ) || '' === trim( $_SERVER['HTTP_REFERER'] ) ) ) {
	secupress_block( 'RMHR', 400 );
}

endif;
