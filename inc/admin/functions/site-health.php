<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_filter( 'site_status_tests', 'secupress_site_status_tests' );
function secupress_site_status_tests( $tests ) {
	$scanners        = secupress_get_scan_results();
	if ( empty( $scanners ) ) {
		return [ 'direct' => [], 'async' => [] ];
	}
	$secupress_tests = secupress_get_scanners();
	foreach ( $secupress_tests as $module_name => $class_name_parts ) {
		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
		foreach ( $class_name_parts as $option_name => $class_name_part ) {
			if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
				unset( $class_name_parts[ $option_name ] );
				continue;
			}
			$tests['direct'][ $option_name ] = [
				'test'  => 'secupress_get_test__' . $option_name,
			];
		}
	}

	unset( $tests['direct']['debug_enabled'], $tests['direct']['plugin_version'], $tests['direct']['theme_version'], $tests['direct']['https_status'], $tests['direct']['php_version'], $tests['direct']['ssl_support'] );
	unset( $tests['async']['background_updates'], $tests['async']['dotorg_communication'] );
	return $tests;
}

// Do you like duplicate code? Because I don't… but I had too, thanks WP.

function secupress_get_test__admin_user() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__easy_login() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__subscription() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__passwords_strength() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_usernames() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__login_errors_disclose() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__plugins_update() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__themes_update() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_old_plugins() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_vuln_plugins() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__inactive_plugins_themes() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__core_update() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__auto_update() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_old_files() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_config_files() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__wp_config() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__db_prefix() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__salt_keys() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__discloses() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__readme_discloses() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__php_disclosure() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__chmods() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__directory_listing() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_file_extensions() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__shellshock() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_user_agent() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__sqli() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__anti_scanner() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_request_methods() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__bad_url_access() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__phpversion() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__php_404() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__wpml_discloses() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__woocommerce_discloses() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__wporg() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

function secupress_get_test__https() {
	$option_name = str_replace( 'secupress_get_test__', '', __FUNCTION__ );
	return secupress_get_test__global( $option_name );
}

/**
 * Add a test to the site health check page from wp 5.2
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @param (string) $option_name
 * @return
 **/
function secupress_get_test__global( $option_name ) {
	secupress_require_class( 'scan' );
	$class_name_part = str_replace( ' ', '_', ucwords( str_replace( '_', ' ', $option_name ) ) );
	$class_name      = 'SecuPress_Scan_' . $class_name_part;
	secupress_require_class( 'scan', $option_name );
	$file_name       = str_replace( '_', '-', strtolower( $class_name_part ) );
	$scanners        = secupress_get_scan_results();
	$fixes           = secupress_get_fix_results();
	$current_test    = $class_name::get_instance();
	$messages        = $current_test::get_messages();
	if ( ! isset( $scanners[ $option_name ] ) ) {
		$result = [
			'label'       => strip_tags( $current_test->title ),
			'status'      => 'good',
			'badge'       => [
				'label'   => __( 'Security' ),
				'color'   => 'blue',
				],
			'description' => '',
			'actions'     => '',
			'test'        => 'secupress_get_test__' . $option_name,
		];
		return $result;
	}
	$message         = secupress_format_message( $scanners[ $option_name ]['msgs'], $class_name_part );
	$message_id      = key( $scanners[ $option_name ]['msgs'] );
	$result = [
		'label'       => strip_tags( $current_test->title ),
		'status'      => 'bad' === $scanners[ $option_name ]['status'] ? 'critical' : 'good',
		'badge'       => [
			'label'   => __( 'Security' ),
			'color'   => 'bad' === $scanners[ $option_name ]['status'] ? 'red' : 'blue',
		],
		'description' => $message . '<br><br><em>' . $current_test->more . '</em>',
		'actions'     => sprintf(
				'<p><a href="%s">%s</a> or <a href="%s" target="_blank" rel="noopener noreferrer">%s<span class="screen-reader-text">%s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
				esc_url( secupress_admin_url( 'scanners', '#' . $class_name_part ) ),
				__( 'Open the scanners', 'secupress' ),
				esc_url( $current_test::get_docs_url() ),
				__( 'Read the documentation', 'secupress' ),
				__( '(opens in a new tab)', 'secupress' )
			),
		'test'        => 'secupress_get_test__' . $option_name,
	];

	return $result;
}


add_action( 'load-site-health.php', 'secupress_replace_progress_count' );
function secupress_replace_progress_count() {
	$i18n          = [];
	$counts        = secupress_get_scanner_counts();
	$i18n['grade'] = $counts['grade'];
	$scanners = secupress_get_scan_results();
	if ( empty( $scanners ) ) {
		$i18n['caution'] = sprintf( esc_html__( '<hr><strong>No status yet, please run the <a href="%s">%s scanners</a> first.</strong><hr>', 'secupress' ), secupress_admin_url( 'scanners' ), SECUPRESS_PLUGIN_NAME );
	}
	wp_localize_script( 'jquery', 'SecuPressi18nSHC', $i18n );
}
