<?php
/*
Module Name: WP Version JS disclose
Description: Remove the WordPress version from the script tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


// Replace the WordPress version with a fake version.

add_filter( 'script_loader_src', 'secupress_replace_wp_version_in_src', PHP_INT_MAX );

if ( ! function_exists( 'secupress_replace_wp_version_in_src' ) ) :
	function secupress_replace_wp_version_in_src( $src ) {
		return str_replace( 'ver=' . get_bloginfo( 'version' ), 'ver=42.0', $src );
	}
endif;
