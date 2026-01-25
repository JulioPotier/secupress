<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

add_filter( 'admin_body_class', 'secupress_contextual_help_add_css_body_class' );
/**
 * Add the no contexttual help as css class
 *
 * @since 2.3.18
 * @author Julio Potier
 * 
 * @param (string) $classes
 * @return (string) $classes
 **/
function secupress_contextual_help_add_css_body_class( $classes ) {
	if ( ! secupress_show_contextual_help() && isset( $_GET['page'] ) && strpos( $_GET['page'], SECUPRESS_PLUGIN_SLUG ) !== false ) {
		$classes .= ' no-contextual-help-secupress'; // do not start with "secupress-"
	}
	return $classes;
}
