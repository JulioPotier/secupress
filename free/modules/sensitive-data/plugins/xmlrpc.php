<?php
/**
 * Module Name: Disable XML-RPC
 * Description: Disable totally or partially XML-RPC.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


add_action( 'secupress.plugins.loaded', 'secupress_xmlrpc_disable_rpc' );
/**
 * Disable XML-RPC by launching and removing hooks.
 *
 * @since 1.0
 */
function secupress_xmlrpc_disable_rpc() {
	$options   = secupress_get_module_option( 'wp-endpoints_xmlrpc', array(), 'sensitive-data' );
	$options   = array_flip( $options );
	$is_xmlrpc = defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;

	// Disable the whole XML-RPC feature.
	if ( isset( $options['block-all'] ) ) {

		// Well, why not killing everything here?
		if ( $is_xmlrpc ) {
			secupress_die(
				__( 'XML-RPC services are disabled on this site.', 'secupress' ),
				__( 'XML-RPC is disabled', 'secupress' ),
				array( 'response' => 403, 'force_die' => true )
			);
		}

		// Disable XML-RPC, just for decorum.
		add_filter( 'xmlrpc_enabled', '__return_false' );

		// Remove RSD link from the page header.
		remove_action( 'wp_head', 'rsd_link' );

		// Remove Pingback header.
		add_filter( 'wp_headers', 'secupress_xmlrpc_remove_pingback_header', 11 );

		// Kill the pingback URL.
		add_filter( 'bloginfo_url', 'secupress_xmlrpc_kill_pingback_url', 10, 2 );

	} elseif ( isset( $options['block-multi'] ) && $is_xmlrpc ) {

		// Disable the multiple authentications.
		add_filter( 'xmlrpc_methods', 'secupress_xmlrpc_remove_multicall_methods', 0 );
		add_filter( 'authenticate',   'secupress_xmlrpc_block_multiauth_attempts', 0, 3 );
	}
}


/**
 * Filter the HTTP headers before they're sent to the browser.
 * Remove the `X-Pingback` header.
 *
 * @since 1.0
 *
 * @param (array) $headers List of headers.
 *
 * @return (array)
 */
function secupress_xmlrpc_remove_pingback_header( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
}


/**
 * Filter the URL returned by get_bloginfo().
 * Disable the pingback URL.
 *
 * @since 1.0
 *
 * @param (mixed) $output The URL returned by bloginfo().
 * @param (mixed) $show   Type of information requested.
 *
 * @return (mixed) Return false if it's the pingback URL.
 */
function secupress_xmlrpc_kill_pingback_url( $output, $show ) {
	return 'pingback_url' === $show ? false : $output;
}


/**
 * Filter the methods exposed by the XML-RPC server.
 * Remove system multicall.
 *
 * @since 1.0
 *
 * @param (array) $methods An array of XML-RPC methods.
 *
 * @return (array)
 */
function secupress_xmlrpc_remove_multicall_methods( $methods ) {
	unset( $methods['system.multicall'], $methods['system.listMethods'], $methods['system.getCapabilities'] );
	return $methods;
}


/**
 * Filter whether a set of user login credentials are valid.
 * Disable XML-RPC multiauth.
 *
 * @since 1.0
 *
 * @param (null|object) $user     WP_User if the user is authenticated. WP_Error or null otherwise.
 * @param (string)      $username User login.
 * @param (string)      $password User password.
 *
 * @return (null|object)
 */
function secupress_xmlrpc_block_multiauth_attempts( $user, $username, $password ) {
	static $credentials;

	if ( empty( $credentials ) ) {
		$credentials = compact( 'username', 'password' );
		return $user;
	}

	if ( $username === $credentials['username'] && $password === $credentials['password'] ) {
		return $user;
	}

	secupress_die(
		__( 'XML-RPC services are disabled on this site.', 'secupress' ),
		__( 'XML-RPC is disabled', 'secupress' ),
		array( 'response' => 403 )
	);
}
