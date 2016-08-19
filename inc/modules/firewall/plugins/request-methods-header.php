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


add_filter( 'http_request_args', 'secupress_bbrm_maybe_add_local_argument', 1000 );
/**
 * Filter the arguments used in an HTTP request.
 * When `wp_remote_post()` is used, no referrer is sent, so 'RMHR' will block these requests.
 * We'll add a custom argument to allow to "self" post.
 *
 * @since 1.0
 *
 * @param (array) $r  An array of HTTP request arguments.
 *
 * @return (array)
 */
function secupress_bbrm_maybe_add_local_argument( $r ) {
	if ( empty( $r['method'] ) || 'POST' !== strtoupper( $r['method'] ) ) {
		return $r;
	}

	if ( empty( $r['body'] ) ) {
		$r['body'] = 'secupress_bbrmhr_is_local=1';
	} elseif ( is_array( $r['body'] ) ) {
		$r['body']['secupress_bbrmhr_is_local'] = 1;
	} elseif ( is_object( $r['body'] ) ) {
		$r['body']->secupress_bbrmhr_is_local = 1;
	} else {
		$r['body'] .= '&secupress_bbrmhr_is_local=1';
	}

	return $r;
}
