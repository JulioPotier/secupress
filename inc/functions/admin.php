<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Get SecuPress scanner counter(s)
 *
 * @since 1.0
 */
function secupress_get_scanner_counts( $type = '' ) {
	include( SECUPRESS_FUNCTIONS_PATH . '/secupress-scanner.php' );
	global $secupress_tests;
	$scanners = get_option( SECUPRESS_SCAN_SLUG );
	$array_fill_keys = array_fill_keys( array( 'good', 'warning', 'bad' ), 0 );
	$array_count_values = false !== $scanners ? array_count_values( wp_list_pluck( $scanners, 'class' ) ) : array();
	$counts = array_merge( $array_fill_keys, $array_count_values );
	$counts['notscannedyet'] = count( $secupress_tests['high'] ) + count( $secupress_tests['medium'] ) + count( $secupress_tests['low'] ) - array_sum( $counts );
	$counts['total'] = count( $secupress_tests['high'] ) + count( $secupress_tests['medium'] ) + count( $secupress_tests['low'] );
	$percent = floor( $counts['good'] * 100 / $counts['total'] );
	switch( $percent ) {
		case $percent >= 90: $counts['grade'] = 'A'; break;
		case $percent >= 80: $counts['grade'] = 'B'; break;
		case $percent >= 70: $counts['grade'] = 'C'; break;
		case $percent >= 60: $counts['grade'] = 'D'; break;
		case $percent >= 50: $counts['grade'] = 'E'; break;
		default: $counts['grade'] = 'F'; break;
	}
	if ( isset( $counts[ $type ] ) ) {
		return $counts[ $type ];
	}
	return $counts;
}

/**
 * Add SecuPress informations into USER_AGENT
 *
 * @since 1.0
 */
function secupress_user_agent( $user_agent )
{
	
	$bonus = ! secupress_is_white_label() ? '' : '*';
	$bonus .= ! get_secupress_option( 'do_beta' ) ? '' : '+';
	$new_ua = sprintf( '%s;SecuPress|%s%s|%s|%s|%s|;', $user_agent, SECUPRESS_VERSION, $bonus, esc_url( home_url() ) );

    return $new_ua;
}

/**
 * Renew all boxes for everyone if $uid is missing
 *
 * @since 1.0
 *
 * @param (int|null)$uid : a User id, can be null, null = all users
 * @param (string|array)$keep_this : which box have to be kept
 * @return void
 */
function secupress_renew_all_boxes( $uid = null, $keep_this = array() )
{
	// Delete a user meta for 1 user or all at a time
	delete_metadata( 'user', $uid, 'secupress_boxes', null == $uid );

	// $keep_this works only for the current user
	if ( ! empty( $keep_this ) && null != $uid ) {
		if ( is_array( $keep_this ) ) {
			foreach ( $keep_this as $kt ) {
				secupress_dismiss_box( $kt );
			}
		} else {
			secupress_dismiss_box( $keep_this );
		}
	}
}

/**
 * Renew a dismissed error box admin side
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_renew_box( $function, $uid = 0 )
{
	global $current_user;
	$uid = $uid==0 ? $current_user->ID : $uid;
	$actual = get_user_meta( $uid, 'secupress_boxes', true );

	if( $actual && false !== array_search( $function, $actual ) ) {
		unset( $actual[array_search( $function, $actual )] );
		update_user_meta( $uid, 'secupress_boxes', $actual );
	}
}

/**
 * Dismissed 1 box, wrapper of rocket_dismiss_boxes()
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_dismiss_box( $function )
{
	rocket_dismiss_boxes(
		array(
			'box'      => $function,
			'_wpnonce' => wp_create_nonce( 'secupress_ignore_' . $function ),
			'action'   => 'secupress_ignore'
		)
	);
}

/**
 * Is this version White Labeled?
 *
 * @since 1.0
 */
function secupress_is_white_label()
{
	$names = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );
	$options = '';
	foreach( $names as $value )
	{
		$options .= !is_array( get_secupress_option( $value ) ) ? get_secupress_option( $value ) : reset( ( get_secupress_option( $value ) ) );
	}
	return 'a509cac94e0cd8238b250074fe802b90' != md5( $options ); ////
}

/**
 * Reset white label options
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_reset_white_label_values( $hack_post )
{
	// White Label default values - !!! DO NOT TRANSLATE !!!
	$options = get_option( WP_ROCKET_SLUG );
	$options['wl_plugin_name']	= 'SecuPress';
	$options['wl_plugin_slug']	= 'secupress';
	$options['wl_plugin_URI']	= 'http://www.secupress.fr';
	$options['wl_description']	= array( 'The best WordPress security plugin.' );
	$options['wl_author']		= 'WP Media';
	$options['wl_author_URI']	= 'http://www.secupress.fr';
	if ( $hack_post ) {
		// hack $_POST to force refresh of files, sorry
		$_POST['page'] = 'secupress';
	}
	update_option( SECUPRESS_SLUG, $options );
}


/**
 * Create a unique id for some secupress options and functions
 *
 * @since 1.0
 */
function create_secupress_uniqid()
{
	return str_replace( '.', '', uniqid( '', true ) );
}

/**
 * Force our user agent header when we hit our urls
 *
 * @since 1.0
 */
add_filter( 'http_request_args', '__secupress_add_own_ua', 10, 3 );
function __secupress_add_own_ua( $r, $url ) {
	if ( strpos( $url, 'secupress.fr' ) !== false ) {
		$r['user-agent'] = secupress_user_agent( $r['user-agent'] );
	}
	return $r;
}


/**
 * 
 * 
 * @since 1.0
 *
 * @param (string)$page : the last word of the secupress page slug
 * @param (string)$params : required params if needed, never use "?" neither "&" for the first char
*/
function secupress_admin_url( $page, $params = '' )
{
	return admin_url( 'admin.php?' . $params . '&page=secupress_' . $page, 'admin' );
}

add_filter( 'registration_errors', '__secupress_registration_test_errors', PHP_INT_MAX, 2 );
function __secupress_registration_test_errors( $errors, $sanitized_user_login ) {
	if ( ! $errors->get_error_code() && strpos( $sanitized_user_login, 'secupress' ) !== false ) {
		set_transient( 'secupress_registration_test', 'failed', HOUR_IN_SECONDS );
		$errors->add( 'secupress_registration_test', 'secupress_registration_test_failed' );
	}
	return $errors;
}