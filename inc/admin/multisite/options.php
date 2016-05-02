<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get scans et fixes results of subsites, organized by test and site ID.
 * It's a kind of `secupress_get_scan_results()` + `secupress_get_fix_results()` in one function, and for subsites.
 * The "scans et fixes of subsites" are related to the fixes that can't be done from the network admin if we are in a multisite installation.
 *
 * @since 1.0
 *
 * @return (array) The results, like:
 *  array(
 *  	test_name_lower => array(
 *  		site_id => array(
 *  			'scan' => array(
 *  				'status' => 'bad',
 *  				'msgs'   => array( 202 => array( params ) )
 *  			),
 *  			'fix'  => array(
 *  				'status' => 'cantfix',
 *  				'msgs'   => array( 303 => array( params ) )
 *  			)
 *  		)
 *  	)
 *  )
 */
function secupress_get_results_for_ms_scanner_fixes() {
	static $tests;
	// Tests that must be fixed outside the network admin.
	if ( ! isset( $tests ) ) {
		$tests = secupress_get_tests_for_ms_scanner_fixes();

		// Cache transients.
		if ( is_multisite() && ! wp_using_ext_object_cache() ) {
			$tests_lower = array_map( 'strtolower', $tests );
			secupress_load_network_options( $tests_lower, '_site_transient_' . SECUPRESS_SCAN_FIX_SITES_SLUG . '_' );
		}
	}
	// Current results.
	$options   = get_site_option( SECUPRESS_SCAN_FIX_SITES_SLUG, array() );
	$options   = is_array( $options ) ? $options : array();
	$modified  = false;
	$schedules = array();
	$current_site_id       = get_current_blog_id();
	$current_site_modified = false;

	foreach ( $tests as $test_name ) {
		$test_name_lower = strtolower( $test_name );

		// Each test has its own transient.
		$transient = secupress_get_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $test_name_lower );

		if ( false === $transient ) {
			continue;
		}

		// The transient has a value: delete the transient.
		secupress_delete_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $test_name_lower );

		if ( ! $transient || ! is_array( $transient ) ) {
			continue;
		}

		// The option must be edited.
		$modified = true;

		foreach ( $transient as $site_id => $data ) {
			// If the site data is empty or if the scan result is good: remove previous values from the option.
			if ( empty( $data ) || isset( $data['scan']['status'] ) && 'good' === $data['scan']['status'] ) {
				if ( $site_id === $current_site_id && ! empty( $options[ $test_name_lower ][ $site_id ] ) ) {
					$schedules[] = $test_name;
				}

				unset( $options[ $test_name_lower ][ $site_id ] );

				if ( empty( $options[ $test_name_lower ] ) ) {
					unset( $options[ $test_name_lower ] );
				}

				if ( $site_id === $current_site_id ) {
					$current_site_modified = true;
				}
			}
			// The data is not empty: add it to the option.
			else {
				$options[ $test_name_lower ] = isset( $options[ $test_name_lower ] ) ? $options[ $test_name_lower ] : array();
				$options[ $test_name_lower ][ $site_id ] = $data;
			}
		}
	}

	if ( $modified ) {
		// We had transient(s), update the option.
		update_site_option( SECUPRESS_SCAN_FIX_SITES_SLUG, $options );

		if ( $schedules ) {
			// Schedule scan updates.
			secupress_require_class( 'scan' );

			foreach ( $schedules as $test_name ) {
				if ( ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
					continue;
				}

				secupress_require_class( 'scan', $test_name );

				$classname = 'SecuPress_Scan_' . $test_name;

				if ( class_exists( $classname ) ) {
					$classname::get_instance()->schedule_autoscan();
				}
			}
		}

		if ( $current_site_modified ) {
			$current_site_is_empty = true;

			foreach ( $tests as $test_name ) {
				$test_name_lower = strtolower( $test_name );

				if ( ! empty( $options[ $test_name_lower ][ $current_site_id ] ) ) {
					$current_site_is_empty = false;
					break;
				}
			}

			if ( $current_site_is_empty ) {
				/**
				 * Fires if the current site has a non-empty scanner.
				 *
				 * @since 1.0
				 */
				do_action( 'secupress.multisite.empty_results_for_ms_scanner_fixes' );
			}
		}
	}

	return $options;
}
