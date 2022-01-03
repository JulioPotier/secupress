<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Scan and Fix results class.
 *
 * @package SecuPress
 * @since 1.3
 * @author Grégory Viguier
 */
class SecuPress_Scanner_Results {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0';

	/**
	 * Prefix used in the name of the option that stores a scan result.
	 *
	 * @var (string)
	 */
	const SCAN_OPTION_PREFIX = 'secupress_scan_';

	/**
	 * Prefix used in the name of the option that stores a fix result.
	 *
	 * @var (string)
	 */
	const FIX_OPTION_PREFIX = 'secupress_fix_';

	/**
	 * Prefix used in the name of the option that stores scan and fix results for sub-sites (sites of a multisite).
	 *
	 * @var (string)
	 */
	const MS_OPTION_PREFIX = 'secupress_ms_scan_fix_';


	/** Properties. ============================================================================= */

	/**
	 * This is used by the sub-sites results to tell if the current site results have been modified.
	 *
	 * @var (bool)
	 */
	protected static $current_site_modified;


	/** Scan ==================================================================================== */

	/**
	 * Get all scan results.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (array)
	 */
	public static function get_scan_results() {
		$results = array();

		foreach ( static::get_scanners() as $scan_name => $class_name_part ) {
			$result = static::get_scan_result( $scan_name );

			if ( $result ) {
				$results[ $scan_name ] = $result;
			}
		}

		return $results;
	}


	/**
	 * Get a scan result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (array|bool|null) The result as an array. False if no result. Null if the scanner doesn’t exist.
	 */
	public static function get_scan_result( $scan_name ) {
		$result = static::get_scan_raw_result( $scan_name );

		if ( null === $result || false === $result ) {
			return $result;
		}

		// Make sure we have messages.
		if ( ! $result || ! is_array( $result ) || empty( $result['msgs'] ) || ! is_array( $result['msgs'] ) ) {
			static::delete_scan_result( $scan_name );
			return false;
		}

		// Make sure the status is fine.
		if ( empty( $result['status'] ) || ! is_string( $result['status'] ) ) {
			$previous_id = -1;

			// Loop through all messages to get the right status.
			foreach ( $result['msgs'] as $message_id => $message_data ) {
				if ( $message_id < $previous_id ) {
					// If we have more than 1 message, we keep the worst status (biggest message ID).
					continue;
				}

				if ( $message_id < 0 || $message_id >= 400 || ! is_array( $message_data ) ) {
					// The message ID or the message data is invalid.
					unset( $result['msgs'][ $message_id ] );
					continue;
				}

				if ( $message_id < 100 ) {
					$result['status'] = 'good';
				} elseif ( $message_id < 200 ) {
					$result['status'] = 'warning';
				} elseif ( $message_id < 300 ) {
					$result['status'] = 'bad';
				} else {
					$result['status'] = 'cantfix';
				}

				$previous_id = $message_id;
			}

			if ( empty( $result['msgs'] ) ) {
				// There was only 1 message and its ID was invalid (or its data).
				static::delete_scan_result( $scan_name );
				return false;
			}
		}

		// In the same time, when a scan is good, remove the related fix.
		if ( 'good' === $result['status'] && false !== static::get_fix_result( $scan_name ) ) {
			static::delete_fix_result( $scan_name );
		}

		return $result;
	}


	/**
	 * Get a scan raw result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (mixed) The option value. Null if the scanner doesn’t exist.
	 */
	public static function get_scan_raw_result( $scan_name ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return null;
		}

		static::cache_scan_results();

		return get_site_option( static::SCAN_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Delete a scan result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 */
	public static function delete_scan_result( $scan_name ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_scan_results();

		delete_site_option( static::SCAN_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Update a scan result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 * @param (array)  $result    Scan result.
	 */
	public static function update_scan_result( $scan_name, $result ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_scan_results();

		update_site_option( static::SCAN_OPTION_PREFIX . $scan_name, $result );
	}


	/**
	 * Retrieve (and cache) from the DB all scan results at once.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected static function cache_scan_results() {
		static $done = false;

		if ( $done ) {
			return;
		}
		$done = 1;

		$scanners = static::get_scanners();
		$scanners = array_flip( $scanners );

		secupress_load_network_options( $scanners, static::SCAN_OPTION_PREFIX );
	}


	/** Fix ===================================================================================== */

	/**
	 * Get all fix results.
	 *
	 * @since 1.3
	 *
	 * @return (array)
	 */
	public static function get_fix_results() {
		$results = array();

		foreach ( static::get_scanners() as $scan_name => $class_name_part ) {
			$result = static::get_fix_result( $scan_name );

			if ( $result ) {
				$results[ $scan_name ] = $result;
			}
		}

		return $results;
	}


	/**
	 * Get a fix result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (array|bool|null) The result as an array. False if no result. Null if the scanner doesn’t exist.
	 */
	public static function get_fix_result( $scan_name ) {
		$result = static::get_fix_raw_result( $scan_name );

		if ( null === $result || false === $result ) {
			return $result;
		}

		if ( ! $result || ! is_array( $result ) ) {
			static::delete_fix_result( $scan_name );
			return false;
		}

		return $result;
	}


	/**
	 * Get a fix raw result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (mixed) The option value. Null if the scanner doesn’t exist.
	 */
	public static function get_fix_raw_result( $scan_name ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return null;
		}

		static::cache_fix_results();

		return get_site_option( static::FIX_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Delete a fix result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 */
	public static function delete_fix_result( $scan_name ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_fix_results();

		delete_site_option( static::FIX_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Update a fix result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 * @param (array)  $result    Fix result.
	 */
	public static function update_fix_result( $scan_name, $result ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_fix_results();

		update_site_option( static::FIX_OPTION_PREFIX . $scan_name, $result );
	}


	/**
	 * Retrieve (and cache) from the DB all fix results at once.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected static function cache_fix_results() {
		static $done = false;

		if ( $done ) {
			return;
		}
		$done = 1;

		$scanners = static::get_scanners();
		$scanners = array_flip( $scanners );

		secupress_load_network_options( $scanners, static::FIX_OPTION_PREFIX );
	}


	/** Multisite Scan and Fix for sub-sites ==================================================== */

	/**
	 * Get all sub-sites results.
	 *
	 * @since 1.3
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
	public static function get_sub_sites_results() {
		$scanners = static::get_scanners_for_ms_sites();
		$results  = array();

		// Reset the value.
		static::$current_site_modified = false;

		// Get all results.
		foreach ( $scanners as $scan_name => $class_name_part ) {
			$result = static::get_sub_sites_result( $scan_name );

			if ( $result ) {
				$results[ $scan_name ] = $result;
			}
		}

		// If the results changed for the current site and are (now) empty, we will trigger an action.
		if ( static::$current_site_modified ) {
			$current_site_id       = get_current_blog_id();
			$current_site_is_empty = true;

			foreach ( $scanners as $scan_name => $class_name_part ) {
				if ( ! empty( $results[ $scan_name ][ $current_site_id ] ) ) {
					$current_site_is_empty = false;
					break;
				}
			}

			if ( $current_site_is_empty ) {
				/**
				 * Fires if the current site has empty scanner results.
				 *
				 * @since 1.0
				 */
				do_action( 'secupress.multisite.empty_results_for_ms_scanner_fixes' );
			}
		}

		// Reset the value.
		static::$current_site_modified = null;

		return $results;
	}


	/**
	 * Get a sub-sites result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (array|bool|null) The result as an array. False if no result. Null if the scanner doesn’t exist.
	 *  array(
	 *  	site_id => array(
	 *  		'scan' => array(
	 *  			'status' => 'bad',
	 *  			'msgs'   => array( 202 => array( params ) )
	 *  		),
	 *  		'fix'  => array(
	 *  			'status' => 'cantfix',
	 *  			'msgs'   => array( 303 => array( params ) )
	 *  		)
	 *  	)
	 *  )
	 */
	public static function get_sub_sites_result( $scan_name ) {
		$result = static::get_sub_sites_raw_result( $scan_name );

		if ( null === $result || false === $result ) {
			return $result;
		}

		if ( ! $result || ! is_array( $result ) ) {
			static::delete_sub_sites_result( $scan_name );
			return false;
		}

		$scan_name            = strtolower( $scan_name );
		$scan_result_modified = false;
		$current_site_id      = get_current_blog_id();

		foreach ( $result as $site_id => $data ) {
			// If the site data is empty or if the scan result is good: remove previous values from the result.
			if ( empty( $data ) || ! empty( $data['scan']['status'] ) && 'good' === $data['scan']['status'] ) {
				$scan_result_modified = true;

				if ( $site_id === $current_site_id ) {
					static::$current_site_modified = true;
				}

				if ( $site_id === $current_site_id && ! empty( $result[ $site_id ] ) ) {
					static::schedule_autoscan( $scan_name );
				}

				unset( $result[ $site_id ] );
			}
		}

		if ( empty( $result ) ) {
			static::delete_sub_sites_result( $scan_name );
			return false;
		}

		if ( $scan_result_modified ) {
			static::update_sub_sites_result( $scan_name, $result );
		}

		return $result;
	}


	/**
	 * Get a fix raw result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 *
	 * @return (mixed) The option value. Null if the scanner doesn’t exist.
	 */
	public static function get_sub_sites_raw_result( $scan_name ) {
		$scanners  = static::get_scanners_for_ms_sites();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return null;
		}

		static::cache_sub_sites_results();

		return get_site_option( static::MS_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Delete a sub-sites result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 */
	public static function delete_sub_sites_result( $scan_name ) {
		$scanners  = static::get_scanners_for_ms_sites();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_sub_sites_results();

		delete_site_option( static::MS_OPTION_PREFIX . $scan_name );
	}


	/**
	 * Update a sub-sites result.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 * @param (array)  $result    Sub-sites result.
	 */
	public static function update_sub_sites_result( $scan_name, $result ) {
		$scanners  = static::get_scanners_for_ms_sites();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		static::cache_sub_sites_results();

		update_site_option( static::MS_OPTION_PREFIX . $scan_name, $result );
	}


	/**
	 * Retrieve (and cache) from the DB all sub-sites results at once.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected static function cache_sub_sites_results() {
		static $done = false;

		if ( $done ) {
			return;
		}
		$done = 1;

		$scanners = static::get_scanners_for_ms_sites();
		$scanners = array_flip( $scanners );

		secupress_load_network_options( $scanners, static::MS_OPTION_PREFIX );
	}


	/** Tools =================================================================================== */

	/**
	 * Get all scanner names.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (array) An array like `array( 'easy_login' => 'Easy_Login',... )`.
	 */
	public static function get_scanners() {
		static $scanners;

		if ( isset( $scanners ) ) {
			return $scanners;
		}

		$scanners = secupress_get_scanners();
		$temp     = [];
		foreach ( $scanners as $keys ) {
			foreach( $keys as $index => $values ) {
				$temp[] = $values;
			}
		}
		$scanners = $temp;
		$scanners = array_combine( $scanners, $scanners );
		$scanners = array_map( 'strtolower', $scanners );
		$scanners = array_flip( $scanners );

		return $scanners;
	}

	/**
	 * Get scanner names that can't be fixes from the network admin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (array) An array like `array( 'bad_old_plugins' => 'Bad_Old_Plugins',... )`.
	 */
	public static function get_scanners_for_ms_sites() {
		static $scanners;

		if ( isset( $scanners ) ) {
			return $scanners;
		}

		$scanners = secupress_get_tests_for_ms_scanner_fixes();
		$scanners = array_combine( $scanners, $scanners );
		$scanners = array_map( 'strtolower', $scanners );
		$scanners = array_flip( $scanners );

		return $scanners;
	}


	/**
	 * Schedule an auto-scan.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $scan_name Name of the scanner.
	 */
	public static function schedule_autoscan( $scan_name ) {
		$scanners  = static::get_scanners();
		$scan_name = strtolower( $scan_name );

		if ( ! isset( $scanners[ $scan_name ] ) ) {
			return;
		}

		if ( ! file_exists( secupress_class_path( 'scan', $scan_name ) ) ) {
			return;
		}

		secupress_require_class( 'scan' );
		secupress_require_class( 'scan', $scan_name );

		$classname = 'SecuPress_Scan_' . $scanners[ $scan_name ];

		if ( class_exists( $classname ) ) {
			$classname::get_instance()->schedule_autoscan();
		}
	}
}
