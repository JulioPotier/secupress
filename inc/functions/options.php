<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * A wrapper to easily get SecuPress option
 *
 * @since 1.0
 *
 * @param string $option  The option name
 * @param bool   $default (default: false) The default value of option
 * @return mixed The option value
 */
function get_secupress_option( $option, $default = false )
{
	/**
	 * Pre-filter any SecuPress option before read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	$value = apply_filters( 'pre_get_secupress_option_' . $option, NULL, $default );
	if ( NULL !== $value ) {
		return $value;
	}
	$value = isset( $options[ $option ] ) && $options[ $option ] !== '' ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	return apply_filters( 'get_secupress_option_' . $option, $value, $default );
}
