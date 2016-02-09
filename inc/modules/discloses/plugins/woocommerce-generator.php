<?php
/*
Module Name: WooCommerce Generator disclose
Description: Remove the generator meta tag value.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( class_exists( 'WooCommerce' ) ) :

	/**
	 * Remove the generator tag value.
	 *
	 * @since 1.0
	 */
	remove_action( 'get_the_generator_html',  'wc_generator_tag' );
	remove_action( 'get_the_generator_xhtml', 'wc_generator_tag' );

endif;
