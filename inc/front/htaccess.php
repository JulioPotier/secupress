<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Used to flush the .htaccess file
 *
 * @since 1.0
 *
 * @param bool $force (default: false)
 * @return void
 */
function secupress_write_htaccess( $marker, $rules = null ) {
	if ( ! $GLOBALS['is_apache'] || ! $rules ) {
		return;
	}

	if ( ! function_exists( 'get_home_path' ) ) {
		require_once( ABSPATH . 'wp-admin/includes/file.php' );
	}

	$htaccess_file = get_home_path() . '.htaccess';

	if ( is_writable( $htaccess_file ) ) {
		// Update the .htacces file.
		return secupress_put_content( $htaccess_file, $marker, $rules );
	}

	return false;
}


/**
 * Return the markers for htaccess rules
 *
 * @since 1.0
 *
 * @param string $function This suffix can be added
 * @return string $marker Rules that will be printed
 */
function secupress_get_htaccess_marker( $function ) {
	$_function = 'secupress_get_htaccess_' . $function;

	if ( ! function_exists( $_function ) ) {
		return false;
	}

	// Recreate this marker
	$marker = call_user_func( $_function );

	/**
	 * Filter rules added by SecuPress in .htaccess
	 *
	 * @since 1.0
	 *
	 * @param string $marker The content of all rules
	*/
	$marker = apply_filters( 'secupress_htaccess_marker_' . $function, $marker );

	return $marker;
}


function secupress_get_htaccess_ban_ip() {
	$ban_ips = get_option( SECUPRESS_BAN_IP );

	if ( is_array( $ban_ips ) && count( $ban_ips ) ) {
		$content = 'Order Deny,Allow' . PHP_EOL;

		foreach ( $ban_ips as $IP => $time ) {
			$content .= 'Deny from ' . $IP . PHP_EOL;
		}

		return $content;
	}

	return '';
}
