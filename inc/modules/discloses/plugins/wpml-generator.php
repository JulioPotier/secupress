<?php
/*
Module Name: WPML Generator disclose
Description: Remove the generator meta tag.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

global $sitepress;

if ( class_exists( 'SitePress' ) && $sitepress && method_exists( $sitepress, 'meta_generator_tag' ) ) :

	/**
	 * Remove the generator tag from the `<head>`.
	 *
	 * @since 1.0
	 */
	remove_action( 'wp_head', array( $sitepress, 'meta_generator_tag' ) );

endif;
