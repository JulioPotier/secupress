<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get scans et fixes results of sub-sites, organized by test and site ID.
 * It's a kind of `secupress_get_scan_results()` + `secupress_get_fix_results()` in one function, and for sub-sites.
 * The "scans et fixes of subsites" are related to the fixes that can't be done from the network admin if we are in a multisite installation.
 *
 * @since 1.0
 * @since 1.3 Use multiple options instead of 1 option and multiple transients.
 * @author Grégory Viguier
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
	return SecuPress_Scanner_Results::get_sub_sites_results();
}
