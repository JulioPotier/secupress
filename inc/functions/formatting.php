<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Create a URL to easily access to our pages
 *
 * @since 1.0
 *
 * @param (string)$page : the last word of the secupress page slug
 * @param (string)$module : the required module
*/
function secupress_admin_url( $page, $module = false ) {
	$module = $module ? '&module=' . sanitize_key( $module ) : '';
	$page = str_replace( '&', '_', $page );

	return admin_url( 'admin.php?page=secupress_' . sanitize_key( $page ) . $module, 'admin' );
}

/**
 * Gives back the module title
 *
 * @since 1.0
 *
 * @param (string)$module : the desired module
*/
function secupress_get_module_title( $module = false ) {
	$module = $module ? $module : $GLOBALS['modulenow'];

	if ( isset( $GLOBALS['secupress_modules'][ $module ] ) ) {
		return $GLOBALS['secupress_modules'][ $module ]['title'];
	}

	return '';
}

/**
 * Output the $text in a P tag with .description class
 *
 * @since 1.0
 *
 * @param (string)$text : the last word of the secupress page slug
*/
function __secupress_description_module( $text = '' ) {
	if ( '' !== $text ) {
		return '<p class="description">' . $text . '</p>';
	}
}

/**
 * like in_array but for nested arrays
 *
 * @since 1.0
 *
*/
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

/**
 * Return the path to a class.
 *
 * @since 1.0
 *
 * @param (string) $prefix         : only one possible value so far: "scan".
 * @param (string) $class_name_part: the classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
*/
function secupress_class_path( $prefix, $class_name_part = '' ) {
	$folders = array(
		'scan' => 'scanners',
	);

	$prefix = strtolower( str_replace( '_', '-', $prefix ) );

	$class_name_part = strtolower( str_replace( '_', '-', $class_name_part ) );
	$class_name_part = $class_name_part ? '-' . $class_name_part : '';

	return SECUPRESS_CLASSES_PATH . $folders[ $prefix ] . '/class-secupress-' . $prefix . $class_name_part . '.php';
}


/**
 * Require a class.
 *
 * @since 1.0
 *
 * @param (string) $prefix         : only one possible value so far: "scan".
 * @param (string) $class_name_part: the classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
*/
function secupress_require_class( $prefix, $class_name_part = '' ) {
	$path = secupress_class_path( $prefix, $class_name_part );

	if ( $path ) {
		require_once( $path );
	}
}
