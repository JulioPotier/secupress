<?php
/**
 * Module Name: Block functions
 * Description: Block PHP functions in http requests
 * Main Module: firewall
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'secupress.plugins.loaded.front', 'secupress_block_functions_check' );
/**
 * Block PHP functions in http requests
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_block_functions_check() {
	$setting   = array_flip( secupress_get_module_option( 'bbq-url-content_block-functions-sources', [ 'COOKIE' ], 'firewall' ) );
	$data      = [];
	if ( isset( $setting['COOKIE'] ) ) {
		$data  = array_merge( $data, $_COOKIE );
	}
	if ( isset( $setting['POST'] ) ) {
		$data  = array_merge( $data, $_POST );
	}
	if ( isset( $setting['GET'] ) ) {
		$data  = array_merge( $data, $_GET );
	}
	$functions = get_defined_functions();
	$functions = array_merge(
		$functions['internal'],
		$functions['user']
	);
	$intersec  = array_intersect( $functions, $data );

	/**
	 * Gives the posibility to bypass the interdiction
	 * 
	 * @since 2.2.6
	 * @author Julio Potier
	 * 
	 * @param (bool)
	 * @param (string) întersec
	 * 
	 * @return (bool)
	 */
	if ( ! empty( $intersec ) && ! apply_filters( 'secupress.plugins.block_functions.bypass', false, $intersec ) ) {
		secupress_block( 'FUNCTS', [ 'code' => 403, 'b64' => [ 'content' => implode( '', $intersec ) ], 'attack_type' => 'bad_request_content' ] );
	}
}