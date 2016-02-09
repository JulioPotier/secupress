<?php
/*
Module Name: WPML Version JS disclose
Description: Remove the WPML version from the script tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! class_exists( 'SitePress' ) ) {
	return;
}


/**
 * Replace the WPML version with a fake version in script src.
 *
 * @since 1.0
 */
add_filter( 'script_loader_src', 'secupress_replace_wpml_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_wpml_version_in_src' ) ) :
	function secupress_replace_wpml_version_in_src( $src ) {
		$hash = secupress_wpml_get_hash();

		return str_replace( 'ver=' . ICL_SITEPRESS_VERSION, 'ver=' . $hash, $src );
	}
endif;


if ( ! function_exists( 'secupress_wpml_get_hash' ) ) :
	function secupress_wpml_get_hash() {
		static $hash;

		if ( ! isset( $hash ) ) {
			$hash = substr( md5( wp_salt( 'nonce' ) . ICL_SITEPRESS_VERSION ), 2, 6 );
		}

		return $hash;
	}
endif;
