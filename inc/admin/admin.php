<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'admin_post_secupress_fixit', '__secupress_fixit_ajax' );
add_action( 'wp_ajax_secupress_fixit',    '__secupress_fixit_ajax' );

function __secupress_fixit_ajax( $test_name = null ) {

	$test_name = isset( $_GET['test'] )     ? esc_attr( $_GET['test'] ) : $test_name;
	$nonce     = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce']         : 0;
	$nonce     = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_fixit_' . $test_name );

	if ( empty( $test_name ) || ! $nonce || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$response = $classname::get_instance()->fix();
		ob_end_flush();
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $response );
	} else {
		wp_redirect( secupress_admin_url( 'scanners' ) );
		die();
	}
}


add_action( 'admin_post_secupress_manual_fixit', '__secupress_manual_fixit' );
add_action( 'wp_ajax_secupress_manual_fixit',    '__secupress_manual_fixit' );

function __secupress_manual_fixit( $class_name_part = null ) {

	$class_name_part = isset( $_POST['test'] ) ? esc_attr( $_POST['test'] ) : $class_name_part;
	$nonce           = isset( $_POST['secupress_manual_fixit-nonce'] ) ? $_POST['secupress_manual_fixit-nonce'] : 0;
	$nonce           = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_manual_fixit-' . $class_name_part );

	if ( empty( $class_name_part ) || ! $nonce || ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $class_name_part );

	$classname = 'SecuPress_Scan_' . $class_name_part;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$response = $classname::get_instance()->manual_fix();
		ob_end_flush();
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $response );
	} else {
		wp_redirect( secupress_admin_url( 'scanners' ) );
		die();
	}
}


add_action( 'admin_post_secupress_scanner', '__secupress_scanner_ajax' );
add_action( 'wp_ajax_secupress_scanner',    '__secupress_scanner_ajax' );

function __secupress_scanner_ajax( $test_name = null ) {

	$test_name = isset( $_GET['test'] )     ? esc_attr( $_GET['test'] ) : $test_name;
	$nonce     = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce']         : 0;
	$nonce     = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_scanner_' . $test_name );

	if ( empty( $test_name ) || ! $nonce || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$scan_class = $classname::get_instance();
			$response   = $scan_class->scan();
		ob_end_flush();
	}

	$output = array(
		$test_name => array(
			'status'  => secupress_status( $response['status'] ),
			'class'   => sanitize_key( $response['status'] ),
			'message' => '<ul>',
		),
	);

	$messages = $scan_class->get_messages();

	foreach ( $response['msgs'] as $id => $atts ) {

		if ( is_array( $messages[ $id ] ) ) {

			$count  = array_shift( $atts );
			$string = translate_nooped_plural( $messages[ $id ], $count );

		} else {

			$string = $messages[ $id ];

		}

		$output[ $test_name ]['message'] .= '<li>' . ( ! empty( $atts ) ? vsprintf( $string, $atts ) : $messages[ $id ] ) . '</li>';
	}

	$output[ $test_name ]['message'] .= '</ul>';

/*	$times   = (array) get_option( SECUPRESS_SCAN_TIMES );
	$counts  = secupress_get_scanner_counts();
	$percent = floor( $counts['good'] * 100 / $counts['total'] );
	$times[] = array( 'grade' => $counts['grade'], 'percent' => $percent, 'time' => time() );
	$times   = array_filter( array_slice( $times , -5 ) );
	update_option( SECUPRESS_SCAN_TIMES, $times );*/

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $output );
	} else {
		wp_redirect( secupress_admin_url( 'scanners' ) );
		die();
	}
}


/**
 * Link to the configuration page of the plugin
 *
 * @since 1.0
 */
add_filter( 'plugin_action_links_' . plugin_basename( SECUPRESS_FILE ), '__secupress_settings_action_links' );

function __secupress_settings_action_links( $actions ) {
	if ( ! secupress_is_white_label() ) {
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http:/secupress.fr/support/', __( 'Support', 'secupress' ) ) );

		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http://docs.secupress.fr', __( 'Docs', 'secupress' ) ) );
	}

	array_unshift( $actions, sprintf( '<a href="%s">%s</a>', secupress_admin_url( 'settings' ), __( 'Settings' ) ) );

	return $actions;
}


/**
 * Reset White Label values to SecuPress default values
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_resetwl', '__secupress_reset_white_label_values_action' );

function __secupress_reset_white_label_values_action() {
	if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_resetwl' ) ) {
		secupress_reset_white_label_values( true );
	}

	wp_safe_redirect( add_query_arg( 'page', 'secupress_settings', remove_query_arg( 'page', wp_get_referer() ) ) );
	die();
}


/**
 *
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_reset_settings', '__secupress_admin_post_reset_settings' );

function __secupress_admin_post_reset_settings() {
	if ( isset( $_GET['_wpnonce'], $_GET['module'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_reset_' . $_GET['module'] ) ) {
		secupress_install_modules( $_GET['module'] );
	}

	wp_safe_redirect( secupress_admin_url( 'modules', $_GET['module'] ) );
	die();
}


/**
 * White Label the plugin, if you need to
 *
 * @since 1.0
 *
 */
// add_filter( 'all_plugins', '__secupress_white_label' );
function __secupress_white_label( $plugins ) {
	if ( ! secupress_is_white_label() ) {
		return $plugins;
	}

	// We change the plugin's header
	$plugins[ SECUPRESS_PLUGIN_FILE ] = array(
		'Name'        => secupress_get_option( 'wl_plugin_name' ),
		'PluginURI'   => secupress_get_option( 'wl_plugin_URI' ),
		'Version'     => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] : '',
		'Description' => reset( ( secupress_get_option( 'wl_description', array() ) ) ),
		'Author'      => secupress_get_option( 'wl_author' ),
		'AuthorURI'   => secupress_get_option( 'wl_author_URI' ),
		'TextDomain'  => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] : '',
		'DomainPath'  => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] : '',
	);

	return $plugins;
}


/**
 * When you're doing an update, the constant does not contain yet your option or any value, reset and redirect!
 *
 * @since 1.0
 */
// add_action( 'admin_init', '__secupress_check_no_empty_name', 11 ); ////

function __secupress_check_no_empty_name() {
	$wl_plugin_name = trim( secupress_get_option( 'wl_plugin_name' ) );

	if ( empty( $wl_plugin_name ) ) {
		secupress_reset_white_label_values( false );
		wp_safe_redirect( $_SERVER['REQUEST_URI'] );
		die();
	}
}


/**
 * This function will force the direct download of the plugin's options, compressed.
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_export', '__secupress_do_options_export' );

function __secupress_do_options_export() {
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_export' ) ) {
		wp_nonce_ays( '' );
	}

	$filename = sprintf( 'secupress-settings-%s-%s.txt', date( 'Y-m-d' ), uniqid() );
	$gz       = 'gz' . strrev( 'etalfed' );
	$options  = $gz//;
	( serialize( get_option( SECUPRESS_SETTINGS_SLUG ) ), 1 ); // do not use secupress_get_option() here

	nocache_headers();
	@header( 'Content-Type: text/plain' );
	@header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
	@header( 'Content-Transfer-Encoding: binary' );
	@header( 'Content-Length: ' . strlen( $options ) );
	@header( 'Connection: close' );

	echo $options;
	exit();
}


/**
 * Force our user agent header when we hit our urls
 *
 * @since 1.0
 */
add_filter( 'http_request_args', '__secupress_add_own_ua', 10, 3 );

function __secupress_add_own_ua( $r, $url ) {
	if ( false !== strpos( $url, 'secupress.fr' ) ) {
		$r['user-agent'] = secupress_user_agent( $r['user-agent'] );
	}

	return $r;
}


add_filter( 'registration_errors', '__secupress_registration_test_errors', PHP_INT_MAX, 2 );

function __secupress_registration_test_errors( $errors, $sanitized_user_login ) {
	if ( ! $errors->get_error_code() && false !== strpos( $sanitized_user_login, 'secupress' ) ) {
		set_transient( 'secupress_registration_test', 'failed', HOUR_IN_SECONDS );
		$errors->add( 'secupress_registration_test', 'secupress_registration_test_failed' );
	}

	return $errors;
}

/**
 * Register all modules settings
 *
 * @return void
 * @since 1.0
 **/
add_action( 'admin_init', 'secupress_register_all_settings' );

function secupress_register_all_settings() {
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module_data ) {
			secupress_register_setting( $key );
		}
	}
}