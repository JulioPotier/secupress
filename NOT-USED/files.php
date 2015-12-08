<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');


/**
 * Get the name of the folder where SecuPress can store sensitive data.
 * This folder will be located in the `uploads` directory.
 *
 * @since 1.0
 *
 * @return (string).
 */
function secupress_get_data_directory_name() {
	$directory_name = sanitize_title( get_site_option( 'secupress_data_directory_name', '' ) );

	if ( ! $directory_name ) {
		$directory_name = wp_generate_password( 8, false, false );
		$directory_name = sanitize_title( 'secupress-' . $directory_name );
		update_site_option( 'secupress_data_directory_name', $directory_name );
	}

	return $directory_name;
}
