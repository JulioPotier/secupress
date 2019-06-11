<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_filter( 'site_status_tests', 'secupress_site_status_tests' );
function secupress_site_status_tests( $tests ) {
	$secupress_tests = secupress_get_scanners();
	foreach ( $secupress_tests as $module_name => $class_name_parts ) {
		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
		foreach ( $class_name_parts as $option_name => $class_name_part ) {
			if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
				unset( $class_name_parts[ $option_name ] );
				continue;
			}
			$tests['direct'][ $option_name ] = [
				'test'  => 'get_test_secupress__' . $option_name,
			];
		}
	}

	//// refaire les scanners que WP fait
	unset( $tests['direct']['debug_enabled'], $tests['direct']['plugin_version'], $tests['direct']['theme_version'], $tests['direct']['https_status'], $tests['direct']['php_version'], $tests['direct']['ssl_support'] );
	unset( $tests['async']['background_updates'], $tests['async']['dotorg_communication'] );
	return $tests;
}

function get_test_secupress__admin_user() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__easy_login() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__subscription() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__passwords_strength() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_usernames() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__login_errors_disclose() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__plugins_update() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__themes_update() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_old_plugins() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_vuln_plugins() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__inactive_plugins_themes() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__core_update() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__auto_update() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_old_files() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_config_files() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__wp_config() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__db_prefix() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__salt_keys() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__discloses() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__readme_discloses() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__php_disclosure() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__chmods() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__directory_listing() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_file_extensions() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__shellshock() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_user_agent() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__sqli() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__anti_scanner() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__anti_front_brute_force() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_request_methods() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__bad_url_access() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__phpversion() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__php_404() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__wpml_discloses() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__woocommerce_discloses() {
	$option_name = str_replace( 'get_test_secupress__', '', __FUNCTION__ );
	return get_test_secupress__global( $option_name );
}

function get_test_secupress__global( $option_name ) {
	secupress_require_class( 'scan' );
	$class_name_part = str_replace( ' ', '_', ucwords( str_replace( '_', ' ', $option_name ) ) );
	$class_name      = 'SecuPress_Scan_' . $class_name_part;
	secupress_require_class( 'scan', $option_name );
	$file_name       = str_replace( '_', '-', strtolower( $class_name_part ) );
	$scanners        = secupress_get_scan_results();
	$fixes           = secupress_get_fix_results();
	$current_test    = $class_name::get_instance();
	$messages        = $current_test::get_messages();
	$message         = secupress_format_message( $scanners[ $option_name ]['msgs'], $class_name_part );
	$message_id      = key( $scanners[ $option_name ]['msgs'] );
	$result = array(
		'label'       => strip_tags( $current_test->title ),
		'status'      => 'bad' === $scanners[ $option_name ]['status'] ? 'critical' : 'good',
		'badge'       => array(
			'label'   => __( 'Security' ),
			'color'   => 'bad' === $scanners[ $option_name ]['status'] ? 'red' : 'blue',
		),
		'description' => $message . '<br><br><em>' . $current_test->more . '</em>',
		'actions'     => sprintf(
				'<p><a href="%s">%s</a> or <a href="%s" target="_blank" rel="noopener noreferrer">%s<span class="screen-reader-text">%s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
				esc_url( secupress_admin_url( 'scanners', '#' . $class_name_part ) ),
				__( 'Open the scanners' ),
				esc_url( $current_test::get_docs_url() ),
				__( 'Read the documentation' ),
				__( '(opens in a new tab)' )
			),
		'test'        => 'get_test_secupress__' . $option_name,
	);

	return $result;
}
