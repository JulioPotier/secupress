<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


/**
 * Check a  privilege for the DB_USER@DB_NAME on DB_HOST
 *
 * Param @privilege (string) MySQL privilege
 *
 * @since 1.0
 * @return bool
 **/
function secupress_db_access_granted() {
	global $wpdb;
	// get privilege for the WP user
	$results = $wpdb->get_results( 'SHOW GRANTS FOR ' . DB_USER . '@' . DB_HOST );

	$access_granted = false;

	// we got something
	if ( isset( $results[0]->{'Grants for ' . DB_USER . '@' . DB_HOST} ) ) {

		foreach ( $results as $result ) {
			$result = reset( $result );
			// USAGE only is not enought
			if ( preg_match( '/GRANT USAGE ON/', $result ) ) {
				continue;
			}
			$quoted_db_name = preg_quote( DB_NAME );
			$access_granted = preg_match( '/ALL PRIVILEGES ON `?' . $quoted_db_name . '`?|ALL PRIVILEGES ON \*\.\*|GRANT .*, ALTER,.* ON `?' . $quoted_db_name .'`?|GRANT .*, ALTER,.* ON \*\.\*/', $result );

			if ( $access_granted ) {
				break;
			}
		}

		return $access_granted;
	}
}

/**
 * Create a unique and new DB prefix without modifing wp-config.php
 *
 * @return string
 * @since 1.0
 **/
function secupress_create_unique_db_prefix() {
	global $wpdb;
	$new_prefix = $wpdb->prefix;
	$all_tables = $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );
	$all_tables = wp_list_pluck( $all_tables, 'Tables_in_' . DB_NAME . ' (' . $wpdb->prefix . '%)' );
	while ( in_array( $new_prefix . 'posts', $all_tables ) ) {
		$new_prefix = strtolower( 'wp_' . secupress_generate_password( 6, array( 'min' => 'true', 'maj' => false, 'num' => false ) ) . '_' );
	}

	return $new_prefix;
}

/**
 * Return no WP tables, filtered.
 *
 * @since 1.0
 * @return array of DB tables
 **/
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
	$duplicates         = array_filter( $duplicates, function( $a ){ return 1 < $a; } );
	$duplicates         = array_keys( $duplicates );

	$dup_tables = array();
	foreach ( $duplicates as $dup_prefix ) {
		$dup_tables = array_merge( $dup_tables, $wpdb->get_results( "SHOW TABLES LIKE '{$wpdb->prefix}{$dup_prefix}%'" ) );
		$dup_tables = wp_list_pluck( $dup_tables, 'Tables_in_' . DB_NAME . ' (' . $wpdb->prefix . $dup_prefix . '%)' );
	}
	
	$good_tables = array_diff( $all_tables, $dup_tables );
	$good_tables = array_diff( $good_tables, $wp_tables );

	return $good_tables;
}

/**
 * Return correct WP tables
 *
 * @since 1.0
 * @return array of DB tables
 **/
function secupress_get_wp_tables() {
	global $wpdb;
	$wp_tables = $wpdb->tables();
	if ( is_multisite() ) {
		$query = $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $wpdb->sitecategories ) );
	 	if ( ! $wpdb->get_var( $query ) ) {
			unset( $wp_tables['sitecategories'] );
		}
	}

	return $wp_tables;
}


function secupress_get_db_backup_filename() {
	global $wpdb;
	return date( 'Y-m-d-H-i' ) . '.database.' . $wpdb->prefix . '.' . uniqid() . '.sql';
}

function secupress_get_db_tables_content( $tables ) {

	global $wpdb;

	$buffer = '## SecuPress Backup ##' . "\n\n";

	foreach ( $tables as $table ) {

		$table_data = $wpdb->get_results( 'SELECT * FROM ' . $table, ARRAY_A );

		$buffer .= "#---------------------------------------------------------->> \n\n";
		$buffer .= sprintf( "# Dump of table %s #\n", $table );
		$buffer .= "#---------------------------------------------------------->> \n\n";

		$buffer .= sprintf( "DROP TABLE IF EXISTS %s;", $table );

		$show_create_table = $wpdb->get_row( 'SHOW CREATE TABLE ' . $table, ARRAY_A );
		$buffer .= "\n\n" . $show_create_table['Create Table'] . ";\n\n";

		if ( $table_data ) {
			$buffer .= 'INSERT INTO ' . $table . ' VALUES';
			foreach ( $table_data as $row ) {
				if ( ! isset( $values ) ) {
					$values = "\n(";
				} else {
					$values = ",\n(";
				}
				foreach ( $row as $key => $value ) {
					$values .= '"' . $wpdb->escape( $value ) . '",';
				}
				$buffer .= rtrim( $values, ', ' ) . ")";
			}
			unset( $values );
			$buffer .= ";\n\n";
		}
	}

	return $buffer;
}