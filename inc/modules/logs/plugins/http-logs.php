<?php
/**
 * Module Name: HTTP Logs
 * Description: Logs "HTTP requests" on the site.
 * Main Module: logs
 * Author: SecuPress
 * Version: 2.1
 */
return;
defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** INCLUDE AND INITIATE ======================================================================== */
/** --------------------------------------------------------------------------------------------- */

if ( ! did_action( 'secupress.plugins.loaded' ) ) {

	if ( ! class_exists( 'SecuPress_Logs' ) ) {
		secupress_require_class( 'Logs' );
	}

	require_once( SECUPRESS_MODULES_PATH . 'logs/plugins/inc/php/http-logs/class-secupress-http-logs.php' );

	SecuPress_HTTP_Logs::get_instance();
}


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_deactivate_plugin_http_logs' );
add_action( 'secupress.plugins.deactivation',                                         'secupress_deactivate_plugin_http_logs' );
/**
 * Delete logs on module deactivation.
 *
 * @since 2.1
 */
function secupress_deactivate_plugin_http_logs() {
	if ( class_exists( 'SecuPress_HTTP_Logs' ) ) {
		SecuPress_HTTP_Logs::get_instance()->delete_logs();
	}
}

add_filter( 'pre_http_request', 'secupress_plugin_http_logs_block_url', 10, 3 );
function secupress_plugin_http_logs_block_url( $return, $parsed_args, $url ) {
	$http_logs             = get_option( SECUPRESS_HTTP_LOGS );
	$parsed_url            = shortcode_atts( [ 'scheme' => '', 'host' => '', 'path' => '', 'query' => '' ], wp_parse_url( $url ) );

	if ( function_exists( 'wp_kses_bad_protocol' ) ) {
		if ( $parsed_args['reject_unsafe_urls'] ) {
			$url = wp_http_validate_url( $url );
		}
		if ( $url ) {
			$url = wp_kses_bad_protocol( $url, array( 'http', 'https', 'ssl' ) );
		}
	}
	// Do not log errors
	if ( empty( $url ) || empty( $parsed_url['scheme'] ) ) {
		return $return;
	}
	if ( $parsed_args['stream'] ) {
		if ( empty( $parsed_args['filename'] ) ) {
			$parsed_args['filename'] = get_temp_dir() . basename( $url );
		}
		if ( ! wp_is_writable( dirname( $parsed_args['filename'] ) ) ) {
			return $return;
		}
	}
	$wphttp = new WP_Http();
	if ( $wphttp->block_request( $url ) ) {
		unset( $wphttp );
		return $return;
	}
	unset( $wphttp );

	$urls                  = [];
	$urls['host']          = $parsed_url['scheme'] . '://' . untrailingslashit( $parsed_url['host'] );
	if ( isset( $parsed_url['path'] ) ) {
		$urls['path']      = $urls['host'] . $parsed_url['path'];
	}
	if ( isset( $parsed_url['query'] ) ) {
		parse_str( html_entity_decode( $parsed_url['query'] ), $get_params );
		if ( ! empty( $http_logs[ $urls['host'] ]['options']['ignore-param'] ) ) {
			$get_params    = array_diff_key( $get_params, array_flip( $http_logs[ $urls['host'] ]['options']['ignore-param'] ) );
		}
		ksort( $get_params );
		$query             = '?' . http_build_query( $get_params );
		if ( isset( $parsed_url['path'] ) ) {
			$urls['query'] = $urls['host'] . $parsed_url['path'] . '?' . $parsed_url['query'];
		} else {
			$urls['query'] = $urls['host'] . '?' . $parsed_url['query'];
		}
	}

	foreach( $urls as $url ) {
		if ( isset( $http_logs[ $url ] ) ) {
			$index = $http_logs[ $url ]['index'];
			if ( 1 == $index ) {
				return $return; // Not blocked, shouldn't be in settings, but hey…
			}
			if ( 13 > $index ) { // 13 = blocked.
				$offset = secupress_get_http_logs_limits( 'int' )[ $index ];
				if ( $http_logs[ $url ]['last'] + $offset > time() ) {
					error_log(var_export('blocked',1));
					$blocked = true;
				}
			}
			$http_logs[ $url ]['last'] = time();
			update_option( SECUPRESS_HTTP_LOGS, $http_logs );
			if ( 13 == $index || isset( $blocked ) ) {
				$http_logs[ $url ]['hits']++;
				return new WP_Error( 'http_request_failed', sprintf( __( 'This URL has been blocked by %s', 'secupress' ), SECUPRESS_PLUGIN_NAME ) );
			}
		}
	}
	return $return;
}
