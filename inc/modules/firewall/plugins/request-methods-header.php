<?php
/**
 * Module Name: Block Bad Request Methods
 * Description: Block requests methods spotted as potentially dangerous.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! defined( 'DOING_CRON' ) ) {
	// Allow these request methods.
	$methods = array( 'GET' => true, 'POST' => true, 'HEAD' => true );

	if ( ! secupress_is_submodule_active( 'sensitive-data', 'restapi' ) ) {
		// Sub-module not activated === REST API enabled === these methods are also allowed.
		$methods = array_merge( $methods, array( 'PUT' => true, 'PATCH' => true, 'DELETE' => true ) );
	}

	if ( ! isset( $methods[ $_SERVER['REQUEST_METHOD'] ] ) ) {
		secupress_block( 'RMHM', 405 );
	}
}
