<?php
/*
Module Name: WooCommerce Version CSS disclose
Description: Remove the WPML version from the style tags.
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
 *
 * @since 1.0
 */
add_filter( 'style_loader_src', 'secupress_replace_woocommerce_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_woocommerce_version_in_src' ) ) :
	function secupress_replace_woocommerce_version_in_src( $src ) {
		$hash = secupress_woocommerce_get_hash();

		return str_replace( 'ver=' . WC_VERSION, 'ver=' . $hash, $src );
	}
endif;


if ( ! function_exists( 'secupress_woocommerce_get_hash' ) ) :
	function secupress_woocommerce_get_hash() {
		static $hash;

		if ( ! isset( $hash ) ) {
			$hash = substr( md5( wp_salt( 'nonce' ) . WC_VERSION ), 2, 6 );
		}

		return $hash;
	}
endif;
