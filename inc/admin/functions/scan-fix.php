<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
		@set_time_limit( 0 );
		$response = $classname::get_instance()->for_current_site( $for_current_site )->scan();
		/**
		 * $response is an array that MUST contain "status" and MUST contain "msgs".
		 */
		// If the scan is good, remove fix result.
		if ( 'good' === $response['status'] ) {
			SecuPress_Scanner_Results::delete_fix_result( $test_name );
		}
		ob_end_clean();
	}

	if ( $response && $format_response ) {
		$response = array(
			'status'  => secupress_status( $response['status'] ),
			'class'   => sanitize_key( $response['status'] ),
			'message' => isset( $response['msgs'] )    ? secupress_format_message( $response['msgs'], $test_name )    : '',
			'fix_msg' => isset( $response['fix_msg'] ) ? secupress_format_message( $response['fix_msg'], $test_name ) : '',
		);
	}

	return $response;
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
		@set_time_limit( 0 );
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
		@set_time_limit( 0 );
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
