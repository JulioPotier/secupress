<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Used to write in a `.htaccess` file
 *
 * @since 1.0
 *
 * @param (string) $marker        Marker suffix after "SecuPress ".
 * @param (string) $rules         Rules to write in the file. An empty value will remove the previous marker rules.
 * @param (string) $relative_path If the file is not in the site root folder.
 *
 * @return (bool) true on success, false on failure.
 */
function secupress_write_htaccess( $marker, $rules = false, $relative_path = '' ) {
	global $is_apache;
	if ( ! $is_apache ) {
		return false;
	}

	$filesystem    = secupress_get_filesystem();
	$htaccess_path = trailingslashit( secupress_get_home_path() . trim( $relative_path, '/' ) );
	$htaccess_file = $htaccess_path . '.htaccess';

	if ( wp_is_writable( $htaccess_file ) || ! $filesystem->exists( $htaccess_file ) && wp_is_writable( $htaccess_path ) ) {
		// Update the .htaccess file.
		return secupress_put_contents( $htaccess_file, $rules, array( 'marker' => $marker ) );
	}

	return false;
}


/**
 * Return the markers for htaccess rules
 *
 * @since 1.0
 *
 * @param (string) $function This suffix can be added.
 *
 * @return (string) $marker Rules that will be printed.
 */
function secupress_get_htaccess_marker( $function ) {
	$_function = 'secupress_get_htaccess_' . $function;

	if ( ! function_exists( $_function ) ) {
		return false;
	}

	// Recreate this marker.
	$marker = call_user_func( $_function );

	/**
	 * Filter rules added by SecuPress in .htaccess.
	 *
	 * @since 1.0
	 *
	 * @param string $marker The content of all rules.
	*/
	$marker = apply_filters( 'secupress.htaccess.marker_' . $function, $marker );

	return $marker;
}
