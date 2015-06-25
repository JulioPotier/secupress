<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * 
 * 
 * @since 1.0
 *
 * @param (string)$page : the last word of the secupress page slug
 * @param (string)$module : the required module
*/
function secupress_admin_url( $page, $module = false )
{
	$module = $module ? '&module=' . sanitize_key( $module ) : '';
	$page = str_replace( '&', '_', $page );
	return admin_url( 'admin.php?page=secupress_' . sanitize_key( $page ) . $module, 'admin' );
}

function get_secupress_module_title( $module = false ) {
	$module = $module ? $module : $GLOBALS['modulenow'];
	if ( isset( $GLOBALS['secupress_modules'][ $module ] ) ) {
		return $GLOBALS['secupress_modules'][ $module ]['title'];
	}
	return '';
}

function __secupress_description_module( $text = '' ) {
	if ( '' != $text ) {
		return '<p class="description">' . $text . '</p>';
	}
}

if ( ! function_exists( 'in_array_deep' ) ) {
	function in_array_deep( $needle, $haystack ) {
		if ( $haystack ) {
		    foreach ( $haystack as $item ) {
		        if ( $item == $needle || ( is_array( $item ) && in_array_deep( $needle, $item ) ) ) {
		            return true;
				}
			}
		}
	    return false;
	}
}