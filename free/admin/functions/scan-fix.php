<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** SCAN / FIX ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get the result of a scan.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name. Format example: Admin_User (not admin-user).
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the scan for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 */
function secupress_scanit( $test_name, $format_response = false, $for_current_site = false ) {
	$response          = false;
	$formated_response = 'error';

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
		secupress_time_limit( 0 );
		$response = $classname::get_instance()->for_current_site( $for_current_site )->scan();
		/**
		 * $response is an array that MUST contain "status" and MUST contain "msgs".
		 */
		// If the scan is good, remove fix result.
		if ( isset( $response['status'] ) && 'good' === $response['status'] ) {
			SecuPress_Scanner_Results::delete_fix_result( $test_name );
		}
		ob_end_clean();
	}

	if ( $response ) {
		$formated_response = array(
			'status'  => secupress_status( $response['status'] ),
			'class'   => sanitize_key( $response['status'] ),
			'message' => isset( $response['msgs'] )    ? secupress_format_message( $response['msgs'], $test_name )    : '',
			'fix_msg' => isset( $response['fix_msg'] ) ? secupress_format_message( $response['fix_msg'], $test_name ) : '',
		);
	}
	/**
	* Perform action on scanner on each item
	* For info: Check DOING_AJAX, if true, this is out global scanner where all is triggered, if not, this is a one by one
	*
	* @since 2.0
	*
	* @param (string) $test_name
	* @param (array)  $formated_response
	*/
	do_action( 'secupress.scanit.response', $test_name, $formated_response );

	if ( $format_response ) {
		return $format_response;
	}
	return $response;
}

/**
 * Scan a particular test asynchronously with a delay
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $test_name The suffix of the class name. Format example: Admin_User (not admin-user).
 * @param (int)    $delay     A delay in seconds if needed
 */
function secupress_scanit_async( $test_name, $delay = 0 ) {
	$http_args = [
		'timeout'   => 0.01,
		'blocking'  => false,
		'cookies'   => $_COOKIE,
		'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
	];
	$is_subsite     = (int) ( is_multisite() && ! is_network_admin() );
	$site_id        = $is_subsite ? get_current_blog_id() : '';
	$nonce_action   = 'secupress_scanner_' . $test_name . ( $is_subsite ? '-' . $site_id : '' );
	$delay          = max( min( 5, (int) $delay ), 0 );
	$delay          = $delay ? '&delay=' . $delay : '';
	$scanner_url    = admin_url( 'admin-ajax.php?action=secupress_scanner' . $delay . '&test=' . $test_name . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) );
	$scan_nonce_url = add_query_arg( '_wpnonce', wp_create_nonce( $nonce_action ), $scanner_url );
	wp_remote_get( $scan_nonce_url, $http_args );
}


/**
 * Get the result of a fix.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name. Format example: Admin_User (not admin-user).
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the fix for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 */
function secupress_fixit( $test_name, $format_response = false, $for_current_site = false ) {
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
		secupress_time_limit( 0 );
		$response = $classname::get_instance()->for_current_site( $for_current_site )->fix();
		/**
		 * $response is an array that MUST contain "status" and MUST contain "msgs".
		 */
		ob_end_clean();
	}

	if ( $response && $format_response ) {
		$response = array_merge( $response, array(
			'class'   => sanitize_key( $response['status'] ),
			'status'  => secupress_status( $response['status'] ),
			'message' => isset( $response['msgs'] ) ? secupress_format_message( $response['msgs'], $test_name ) : '',
		) );
		unset( $response['msgs'] );
	}

	return $response;
}


/**
 * Get the result of a manual fix.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name.
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the manual fix for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 */
function secupress_manual_fixit( $test_name, $format_response = false, $for_current_site = false ) {
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
		secupress_time_limit( 0 );
		$response = $classname::get_instance()->for_current_site( $for_current_site )->manual_fix();
		/**
		 * $response is an array that MUST contain "status" and MUST contain "msgs".
		 */
		ob_end_clean();
	}

	if ( $response && $format_response ) {
		$response = array_merge( $response, array(
			'class'   => sanitize_key( $response['status'] ),
			'status'  => secupress_status( $response['status'] ),
			'message' => isset( $response['msgs'] ) ? secupress_format_message( $response['msgs'], $test_name ) : '',
		) );
		unset( $response['msgs'] );
	}

	return $response;
}

add_action( 'admin_footer', 'secupress_pre_check_php_version' );
/**
 * Runs a pre check to see if we need to launch a PHPVersion Scanner silently
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @see SecuPress_Scan_PhpVersion
 **/
function secupress_pre_check_php_version() {
	$info     = get_option( 'secupress_scan_phpversion' );
	if ( ! isset( $info['status'] ) || 'bad' !== $info['status'] ) {
		return;
	}
	$versions = secupress_get_php_versions();
	if ( version_compare( $versions['current'], $versions['mini'] ) >= 0 ) {
		secupress_scanit( 'PhpVersion' );
	}
}
