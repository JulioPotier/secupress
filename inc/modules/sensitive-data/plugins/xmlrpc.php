<?php
/*
Module Name: Disable XMLRPC
Description: Disable totally or partially XMLRPC.
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


add_action( 'secupress_plugins_loaded', 'secupress_xmlrpc_disable_rpc' );

function secupress_xmlrpc_disable_rpc() {
	$options = secupress_get_module_option( 'wp-endpoints_xmlrpc', array(), 'sensitive-data' );
	$options = array_flip( $options );

	// Disable the whole XMLRPC feature.
	if ( isset( $options['block-all'] ) ) {
		// Well, why not killing everything here?
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			wp_die(
				__( 'XMLRPC functionality is disabled on this site.', 'secupress' ),
				__( 'XMLRPC is disabled', 'secupress' ),
				array( 'response' => 403 )
			);
		}

		// Disable XMLRPC, just for decorum.
		add_filter( 'xmlrpc_enabled', '__return_false' );

		// Remove RSD link from the page header.
		remove_action( 'wp_head', 'rsd_link' );

		// Remove Pingback header.
		add_filter( 'wp_headers', 'secupress_xmlrpc_remove_pingback_header', 11 );

		// Kill the pingback URL.
		add_filter( 'bloginfo_url', 'secupress_xmlrpc_kill_pingback_url', 10, 2 );
		return;
	}

	// Disable only the multiple authentication attempts.
	////
}


function secupress_xmlrpc_remove_pingback_header( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
}


function secupress_xmlrpc_kill_pingback_url( $output, $show ) {
	return 'pingback_url' === $show ? false : $output;
}
