<?php
/*
Module Name: WP Version JS disclose
Description: Remove the WordPress version from the script tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


/**
 * Replace the WordPress version with a fake version in script src.
 */
add_filter( 'script_loader_src', 'secupress_replace_wp_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_wp_version_in_src' ) ) :
	/**
	 * Replace the WordPress version with a fake version.
	 *
	 * @param (string) $src A content containing the string `ver={$wp_version}`.
	 *
	 * @return (string)
	 */
	function secupress_replace_wp_version_in_src( $src ) {
		$ver  = get_bloginfo( 'version' );
		$hash = secupress_generate_hash( $ver );

		return str_replace( 'ver=' . $ver, 'ver=' . $hash, $src );
	}
endif;
