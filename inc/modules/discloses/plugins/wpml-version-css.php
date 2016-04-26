<?php
/*
Module Name: WPML Version CSS disclose
Description: Remove the WPML version from the style tags.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! class_exists( 'SitePress' ) ) {
	return;
}


/**
 * Replace the WPML version with a fake version in style src.
 */
add_filter( 'style_loader_src', 'secupress_replace_wpml_version_in_src', PHP_INT_MAX );

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


/**
 * Replace the WPML version with a fake version in source code. Let's get dirty.
 * This is required for `language-selector.css` -_-'
 *
 * @since 1.0
 */
add_action( 'widgets_init', 'secupress_wpml_language_selector_widget_init', 8 );

function secupress_wpml_language_selector_widget_init() {
	add_action( 'template_redirect', 'secupress_wpml_icl_lang_sel_nav_ob_start', 0 );
	add_action( 'wp_head',           'secupress_wpml_icl_lang_sel_nav_ob_end' );
}


function secupress_wpml_icl_lang_sel_nav_ob_start() {
	if ( ! is_feed() ) {
		ob_start( 'secupress_wpml_icl_change_lang_sel_nav_version' );
	}
}


function secupress_wpml_icl_lang_sel_nav_ob_end(){
	if ( is_feed() ) {
		return;
	}

	$active_handler = ob_list_handlers();
	$active_handler = array_pop( $active_handler );

	if ( 'secupress_wpml_icl_change_lang_sel_nav_version' === $active_handler ) {
		ob_end_flush();
	}
}


function secupress_wpml_icl_change_lang_sel_nav_version( $buffer ) {
	if ( defined( 'ICL_DONT_LOAD_LANGUAGE_SELECTOR_CSS' ) && ICL_DONT_LOAD_LANGUAGE_SELECTOR_CSS ) {
		return $buffer;
	}

	$hash = secupress_generate_hash( ICL_SITEPRESS_VERSION );

	return str_replace( '?v=' . ICL_SITEPRESS_VERSION . '"', '?v=' . $hash . '"', $buffer );
}
