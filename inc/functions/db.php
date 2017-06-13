<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Check a privilege for the DB_USER@DB_NAME on DB_HOST.
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_db_access_granted() {
	global $wpdb;

	// Get privilege for the WP user.
	$host    = preg_replace( '/:\d+$/', '', DB_HOST );
	$results = $wpdb->get_results( 'SHOW GRANTS FOR ' . DB_USER . '@' . $host ); // WPCS: unprepared SQL ok.

	// We got something.
	if ( ! isset( $results[0]->{'Grants for ' . DB_USER . '@' . $host} ) ) {
		return false;
	}

	$access_granted = false;
	$quoted_db_name = str_replace( '_', '\\\*_', preg_quote( DB_NAME, '/' ) );

	foreach ( $results as $result ) {
		$result = reset( $result );
		// USAGE only is not enought.
		if ( preg_match( '/GRANT USAGE ON/', $result ) ) {
			continue;
		}

		$access_granted = preg_match( '/ALL PRIVILEGES ON `?' . $quoted_db_name . '`?|ALL PRIVILEGES ON \*\.\*|GRANT .*, ALTER,.* ON `?' . $quoted_db_name . '`?|GRANT .*, ALTER,.* ON \*\.\*/', $result );

		if ( $access_granted ) {
			break;
		}
	}

	return $access_granted;
}


/**
 * Create a unique and new DB prefix without modifing `wp-config.php`.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_create_unique_db_prefix() {
	global $wpdb;

	$new_prefix = $wpdb->prefix;
	$all_tables = $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );
	$all_tables = wp_list_pluck( $all_tables, 'Tables_in_' . DB_NAME . ' (' . $wpdb->prefix . '%)' );
	$all_tables = array_flip( $all_tables );

	while ( isset( $all_tables[ $new_prefix . 'posts' ] ) ) {
		$new_prefix = strtolower( 'wp_' . strtolower( secupress_generate_key( 6 ) ) . '_' );
	}

	return $new_prefix;
}


/**
 * Return no WP tables, filtered.
 *
 * @since 1.0
 *
 * @return (array) An array of DB tables.
 */
function secupress_get_non_wp_tables() {
	global $wpdb;

	$wp_tables     = secupress_get_wp_tables();
	$all_tables    = $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );
	$all_tables    = wp_list_pluck( $all_tables, 'Tables_in_' . DB_NAME . ' (' . $wpdb->prefix . '%)' );
	$test_tables   = array();
	$prefixes      = array( $wpdb->prefix );

	$merges_values = array_reverse( $wp_tables );
	$merges_values = array_keys( $merges_values );
	$merges_values = array_merge( $merges_values, $prefixes );

	foreach ( $all_tables as $table ) {
		$test_tables[] = str_replace( $merges_values, '', $table );
	}

	$test_tables_filter = array_filter( $test_tables );
	$test_tables_unique = array_flip( $test_tables_filter );
	$test_tables_unique = array_keys( $test_tables_unique );
	$duplicates         = array_count_values( $test_tables_filter );
	$duplicates         = array_filter( $duplicates, 'secupress_filter_greater_than_1' );
	$duplicates         = array_keys( $duplicates );
	$dup_tables         = array();

	foreach ( $duplicates as $dup_prefix ) {
		$dup_tables = array_merge( $dup_tables, $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}{$dup_prefix}%'" ) ); // WPCS: unprepared SQL ok.
		$dup_tables = wp_list_pluck( $dup_tables, 'Tables_in_' . DB_NAME . ' (' . $wpdb->prefix . $dup_prefix . '%)' );
	}

	$good_tables = array_diff( $all_tables, $dup_tables );
	$good_tables = array_diff( $good_tables, $wp_tables );

	return $good_tables;
}


/**
 * Used as callback for `array_filter()`: keep rows where the value is greater than 1.
 *
 * @since 1.0
 *
 * @param (array) $value The value to test.
 *
 * @return (bool)
 */
function secupress_filter_greater_than_1( $value ) {
	return 1 < $value;
}


/**
 * Return correct WP tables.
 *
 * @since 1.0
 *
 * @return (array) An array of DB tables.
 */
function secupress_get_wp_tables() {
	global $wpdb;

	$wp_tables = $wpdb->tables();

	if ( is_multisite() ) {
		$query = $wpdb->prepare( 'SHOW TABLES LIKE %s', secupress_esc_like( $wpdb->sitecategories ) );
	 	if ( ! $wpdb->get_var( $query ) ) { // WPCS: unprepared SQL ok.
			unset( $wp_tables['sitecategories'] );
		}
	}

	return $wp_tables;
}
