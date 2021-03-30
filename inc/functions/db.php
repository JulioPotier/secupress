<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Return the filepath where the $table_prefix global is set.
 * Don’t get me wrong, you have to give him the correct file, it won't search for you.
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @global $wpdb
 * @return (string|bool) Filepath or false
 **/
function secupress_where_is_table_prefix() {
	global $wpdb;

	$config_filepath = secupress_is_wpconfig_writable( 'db' );
	if ( $config_filepath ) {
		$regex_pattern = '/(\$table_prefix\s*=\s*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");).*|(\$GLOBALS\[\'table_prefix\'\]\s*=\s*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");).*/';
		$file_content  = file_get_contents( $config_filepath );

		return preg_match( $regex_pattern, $file_content ) ? $config_filepath : false;
	}
	return false;
}

function secupress_change_db_prefix( $new_prefix, $tables ) {
	global $wpdb, $table_prefix;

	$old_prefix = $wpdb->prefix;
	if ( $new_prefix === $old_prefix ) {
		return -1;
	}
	$new_prefix = preg_replace( '/[^A-Za-z0-9\_]/', '', $new_prefix );
	$new_prefix = rtrim( $new_prefix, '_' ) . '_';
	if ( strlen( $new_prefix ) === 1 ) {
		return -2;
	}
	if ( ! secupress_db_access_granted() ) {
		return -3;
	}
	$non_wp_tables    = secupress_get_non_wp_tables();
	$wp_tables        = secupress_get_wp_tables();
	$tables           = is_array( $tables ) ? $tables : [];
	$tables_to_rename = array_merge( array_intersect( $non_wp_tables, $tables ), array_values( $wp_tables ) );

	$wpconfig_filepath = secupress_where_is_table_prefix();
	if ( ! $wpconfig_filepath ) {
		return -4;
	}

	// Let's start.
	$query_tables = [];

	// Tables for multisite.
	if ( is_multisite() ) {
		$blog_ids = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs} WHERE blog_id > 1" );

		if ( $blog_ids ) {
			foreach ( $blog_ids as $blog_id ) {
				$tables = $wpdb->tables( 'blog' );

				foreach ( $tables as $table ) {
					$tables_to_rename[] = substr_replace( $table, $old_prefix . $blog_id . '_', 0, strlen( $old_prefix ) );
				}
			}
		}
	}

	// Build the query to rename the tables.
	foreach ( $tables_to_rename as $table ) {
		$new_table      = substr_replace( $table, $new_prefix, 0, strlen( $wpdb->prefix ) );
		$query_tables[] = "`{$table}` TO `{$new_table}`";
	}

	$wpdb->query( 'RENAME TABLE ' . implode( ', ', $query_tables ) ); // WPCS: unprepared SQL ok.

	// Test if we succeeded.
	$options_tables = $wpdb->get_col( "SHOW TABLES LIKE '{$new_prefix}options'" ); // WPCS: unprepared SQL ok.

	if ( reset( $options_tables ) !== $new_prefix . 'options' ) { // WPCS: unprepared SQL ok.
		return -5;
	}

	// We must not forget to change the prefix attribute for future queries.
	$table_prefix = $new_prefix; // WPCS: override ok.
	$wpdb->set_prefix( $table_prefix );
	$wpdb->prefix = $table_prefix; // WPCS: override ok.

	// Some values must be updated.
	$old_prefix_len  = strlen( $old_prefix );
	$old_prefix_len1 = $old_prefix_len + 1;
	$wpdb->update( $new_prefix . 'options', array( 'option_name' => $new_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
	$wpdb->query( "UPDATE {$new_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$new_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.

	if ( ! empty( $blog_ids ) ) {
		foreach ( $blog_ids as $blog_id ) {
			$old_prefix_len  = strlen( $old_prefix ) + strlen( $blog_id ) + 1; // + 1 = "_"
			$old_prefix_len1 = $old_prefix_len + 1;
			$ms_prefix       = $new_prefix . $blog_id . '_';

			$wpdb->update( $ms_prefix . 'options', array( 'option_name' => $ms_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
			$wpdb->query( "UPDATE {$ms_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$ms_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.
		}
	}

	// $table_prefix = 'foobar';
	secupress_replace_content(
		$wpconfig_filepath,
		'@^[\t ]*?\$table_prefix\s*=\s*(?:\'' . $old_prefix . '\'|"' . $old_prefix . '")\s*;.*?$@mU',
		'$table_prefix = \'' . $new_prefix . "'; // Modified by SecuPress.\n/** Commented by SecuPress. */ // $0"
	);
	// $GLOBALS['table_prefix'] = 'foobar';
	secupress_replace_content(
		$wpconfig_filepath,
		'@^[\t ]*?\$GLOBALS\[\'table_prefix\']\s*=\s*(?:\'' . $old_prefix . '\'|"' . $old_prefix . '")\s*;.*?$@mU',
		'$GLOBALS[\'table_prefix\'] = \'' . $new_prefix . "'; // Modified by SecuPress.\n/** Commented by SecuPress. */ // $0"
	);

	// Wait 3 seconds to prevent redirection on install.php
	sleep( 3 );

	secupress_scanit( 'DB_Prefix' );

	return $new_prefix;
}
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

	/**
	* Filter the Non WordPress Tables
	* @param (array) $good_tables
	*/
	return apply_filters( 'secupress.get_non_wp_tables', $good_tables );
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
	if ( secupress_is_submodule_active( 'firewall', 'geoip-system' ) ) {
		$wp_tables['secupress_geoips'] = $wpdb->prefix . 'secupress_geoips';
	}

	if ( is_multisite() ) {
		$query = $wpdb->prepare( 'SHOW TABLES LIKE %s', secupress_esc_like( $wpdb->sitecategories ) );
	 	if ( ! $wpdb->get_var( $query ) ) { // WPCS: unprepared SQL ok.
			unset( $wp_tables['sitecategories'] );
		}
	}

	/**
	* Filter the WordPress Tables
	* @param (array) $wp_tables
	*/
	return apply_filters( 'secupress.get_wp_tables', $wp_tables );
}


/**
 * Get salt keys.
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (array)
 */
function secupress_get_db_salt_keys() {
	return [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ];
}


/**
 * Delete DB salt keys.
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (bool) true: nothing delete or everything deleted, false: missing deletion, keys still in DB
 */
function secupress_delete_db_salt_keys() {
	$keys    = secupress_get_db_salt_keys();
	$present = 0;
	$deleted = 0;
	foreach ( $keys as $key ) {
		$key = strtolower( $key );
		$db  = get_site_option( $key, null );
		if ( ! is_null( $db ) ) {
			$present++;
			if ( delete_site_option( $key ) ) {
				$deleted++;
			}
		}
	}

	return 0 === ( $present - $deleted );
}
