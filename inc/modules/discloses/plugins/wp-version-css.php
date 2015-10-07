<?php
/*
Module Name: WP Version CSS disclose
Description: Remove the WordPress version from the style tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


// Replace the WordPress version with a fake version.

add_filter( 'style_loader_src', 'secupress_replace_wp_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_wp_version_in_src' ) ) :
	function secupress_replace_wp_version_in_src( $src ) {
		static $hash;

		$ver  = get_bloginfo( 'version' );
		$hash = isset( $hash ) ? $hash : substr( md5( wp_salt( 'nonce' ) . $ver ), 2, 6 );

		return str_replace( 'ver=' . $ver, 'ver=' . $hash, $src );
	}
endif;
