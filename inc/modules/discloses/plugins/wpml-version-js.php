<?php
/**
 * Module Name: WPML Version JS disclosure
 * Description: Remove the WPML version from the script tags.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 1.0
 */
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! class_exists( 'SitePress' ) ) {
	return;
}


/**
 * Replace the WPML version with a fake version in script src.
 */
add_filter( 'script_loader_src', 'secupress_replace_wpml_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_wpml_version_in_src' ) ) :
	/**
	 * Replace the WPML version with a fake version.
	 *
	 * @param (string) $src A content containing the string `ver={$wpml_version}`.
	 *
	 * @return (string)
	 */
	function secupress_replace_wpml_version_in_src( $src ) {
		$hash = secupress_generate_hash( ICL_SITEPRESS_VERSION );

		return str_replace( 'ver=' . ICL_SITEPRESS_VERSION, 'ver=' . $hash, $src );
	}
endif;
