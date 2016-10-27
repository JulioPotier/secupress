<?php
/*
Module Name: WooCommerce Version CSS disclose
Description: Remove the WooCommerce version from the style tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! class_exists( 'WooCommerce' ) ) {
	return;
}


/**
 * Replace the WooCommerce version with a fake version in style src.
 */
add_filter( 'style_loader_src', 'secupress_replace_woocommerce_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_woocommerce_version_in_src' ) ) :
	/**
	 * Replace the WooCommerce version with a fake version.
	 *
	 * @param (string) $src A content containing the string `ver={$wc_version}`.
	 *
	 * @return (string)
	 */
	function secupress_replace_woocommerce_version_in_src( $src ) {
		$hash = secupress_generate_hash( WC_VERSION );

		return str_replace( 'ver=' . WC_VERSION, 'ver=' . $hash, $src );
	}
endif;
