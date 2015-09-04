<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_post_secupress_fixit', '__secupress_fixit_ajax' );
add_action( 'wp_ajax_secupress_fixit', '__secupress_fixit_ajax' );
function __secupress_fixit_ajax() {
	if ( isset( $_GET['prio'], $_GET['test'], $_GET['_wpnonce'] ) ) {
		$this_test = $_GET['test'];
		wp_verify_nonce( $_GET['_wpnonce'], 'secupress_fixit_' . $this_test ) or wp_nonce_ays( '' );
		if ( function_exists( 'secupress_fix_' . $this_test ) ) {
			ob_start();
				$response = call_user_func( 'secupress_fix_' . $this_test );
				// if ( time() % 2 == 0 ) {
				// 	$response = array( 'status' => 'Good' );
				// }

			ob_end_flush();
		}
	}
}

add_action( 'admin_post_secupress_scanner', '__secupress_scanner_ajax' );
add_action( 'wp_ajax_secupress_scanner', '__secupress_scanner_ajax' );
function __secupress_scanner_ajax( $this_test = null, $prio = null ) {
	$this_test = isset( $_GET['test'] ) ? $_GET['test'] : $this_test;
	$nonce = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce'] : 0;
	$nonce = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_scanner_' . $this_test );
	$prio_key = isset( $_GET['prio'] ) ? $_GET['prio'] : $prio;
	if ( ! empty( $this_test ) && ! empty( $prio_key ) ) {
		
		require_once( SECUPRESS_FUNCTIONS_PATH . '/scanners-functions.php' );
		require_once( SECUPRESS_FUNCTIONS_PATH . '/secupress-scanner.php' );
		foreach( $secupress_tests[ $prio_key ] as $test_name => $test ) {
			@set_time_limit( 0 );
			if ( ( $this_test == null || $this_test == 'all' || $this_test == $test_name ) && is_callable( array( 'SecuPress_Scanners_Functions', $test_name ) ) ) {
				ob_start();
					$response = call_user_func( array( 'SecuPress_Scanners_Functions', $test_name ) );
					// if ( time() % 2 == 0 ) {
					// 	$response = array( 'status' => 'Good' );
					// }

				ob_end_flush();
				$results = array_filter( (array) get_option( SECUPRESS_SCAN_SLUG ) );
				unset( $results[ $test_name ] );
				$results[ $test_name ]['status'] = secupress_status( $response['status'] );
				$results[ $test_name ]['class']  = sanitize_key( $response['status'] );
				if ( isset( $test[ 'msg_' . sanitize_key( $response['status'] ) ] ) ) {
					$results[ $test_name ]['message'] = sprintf( $test[ 'msg_' . sanitize_key( $response['status'] ) ], isset( $response['message'] ) ? $response['message'] : '' );
				} elseif ( isset( $response['message'] ) ) {
					$results[ $test_name ]['message'] = $response['message'];
				}
				update_option( SECUPRESS_SCAN_SLUG, $results );
				$times = (array) get_option( SECUPRESS_SCAN_TIMES );
				$counts = secupress_get_scanner_counts();
				$percent = floor( $counts['good'] * 100 / $counts['total'] );
				$times[] = array( 'grade' => $counts['grade'], 'percent' => $percent, 'time' => time() );
				$times = array_filter( array_slice( $times , -5 ) );
				update_option( SECUPRESS_SCAN_TIMES, $times );
			}
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_success( $results );
		} else {
			wp_redirect( secupress_admin_url( 'scanner' ) );
			die();
		}
	} else {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
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
 * Add the CSS and JS files for SecuPress scanners page
 *
 * @since 1.0
 */
add_action( 'admin_print_styles-secupress_page_secupress_scanner', '__secupress_scanner_add_admin_css_js' ); //// dédoublonner
function __secupress_scanner_add_admin_css_js() {
	$suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	wp_enqueue_script( 'secupress-scanner-js', SECUPRESS_ADMIN_JS_URL . 'secupress-scanner.js', null, SECUPRESS_VERSION, true );
	wp_enqueue_script( 'secupress-chartjs', SECUPRESS_ADMIN_JS_URL . 'Chart' . $suffix . '.js', null, '1.0.2.1', true );
	wp_enqueue_script( 'jquery-timeago', SECUPRESS_ADMIN_JS_URL . 'jquery.timeago.js', null, '1.4.1', true );
	wp_enqueue_style( 'secupress-scanner-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-scanner.css', null, SECUPRESS_VERSION );
	$counts = secupress_get_scanner_counts();
	wp_localize_script( 'secupress-chartjs', 'SecuPressi18nChart',
		array(
			'good' => array( 'value' => $counts['good'], 'text' => __( 'Good', 'secupress' ) ),
			'warning' => array( 'value' => $counts['warning'], 'text' => __( 'Warning', 'secupress' ) ),
			'bad' => array( 'value' => $counts['bad'], 'text' => __( 'Bad', 'secupress' ) ),
			'notscannedyet' => array( 'value' => $counts['notscannedyet'], 'text' => __( 'Not Scanned Yet', 'secupress' ) ),
		)
	);
}

/**
 * Add the CSS and JS files for SecuPress settings page
 *
 * @since 1.0
 */
add_action( 'admin_print_styles-secupress_page_secupress_settings', '__secupress_settings_add_admin_css', 99999 );
function __secupress_settings_add_admin_css() {
	wp_enqueue_style( 'secupress-settings-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-settings.css', null, SECUPRESS_VERSION );
}

/**
 * Add the CSS and JS files for SecuPress modules page
 *
 * @since 1.0
 */
add_action( 'admin_print_styles-' . SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules', '__secupress_modules_add_admin_css' );
function __secupress_modules_add_admin_css() {
	wp_enqueue_style( 'secupress-modules-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-modules.css', null, SECUPRESS_VERSION );
}


/**
 * Add the CSS and JS files for SecuPress modules page
 *
 * @since 1.0
 */
add_action( 'admin_print_scripts-secupress_page_secupress_modules', '__secupress_modules_add_admin_js' );
function __secupress_modules_add_admin_js() {
	wp_enqueue_script( 'secupress-zxcvbn-async', includes_url( '/js/zxcvbn.min.js' ), array( 'jquery' ) );
	wp_enqueue_script( 'secupress-modules-js', SECUPRESS_ADMIN_JS_URL . 'secupress-modules.js', array( 'jquery', 'secupress-zxcvbn-async', 'password-strength-meter' ), SECUPRESS_VERSION, true );
	wp_localize_script( 'secupress-modules-js', 'l10nmodules', array( 'selectOneRoleMinimum' => __( 'Select 1 role minimum', 'secupress' ) ) );
	wp_localize_script( 'password-strength-meter', 'pwsL10n', array(
    'empty' => __( 'Enter a password', 'secupress' ),
    'short' => __( 'Very weak' ),
    'bad' => __( 'Weak' ),
    'good' => _x( 'Medium', 'password strength' ),
    'strong' => __( 'Strong' ),
    'mismatch' => __( 'Mismatch' )
) );
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
 * White Label the plugin, if you need to
 *
 * @since 1.0
 *
 */
// add_filter( 'all_plugins', '__secupress_white_label' );
function __secupress_white_label( $plugins ) {
	if ( secupress_is_white_label() ) {
		// We change the plugin's header
		$plugins[ SECUPRESS_PLUGIN_FILE ] = array(
				'Name'			=> get_secupress_option( 'wl_plugin_name' ),
				'PluginURI'		=> get_secupress_option( 'wl_plugin_URI' ),
				'Version'		=> isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] : '',
				'Description'	=> reset( ( get_secupress_option( 'wl_description', array() ) ) ),
				'Author'		=> get_secupress_option( 'wl_author' ),
				'AuthorURI'		=> get_secupress_option( 'wl_author_URI' ),
				'TextDomain'	=> isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] : '',
				'DomainPath'	=> isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] : '',
			);
	}
	return $plugins;
}

/**
 * When you're doing an update, the constant does not contain yet your option or any value, reset and redirect!
 *
 * @since 1.0
 */
// add_action( 'admin_init', '__secupress_check_no_empty_name', 11 ); ////
function __secupress_check_no_empty_name() {
	$wl_plugin_name = trim( get_secupress_option( 'wl_plugin_name' ) );
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
	$gz = 'gz' . strrev( 'etalfed' );
	$options = $gz//;
	( serialize( get_option( SECUPRESS_SETTINGS_SLUG ) ), 1 ); // do not use get_secupress_option() here
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
	if ( strpos( $url, 'secupress.fr' ) !== false ) {
		$r['user-agent'] = secupress_user_agent( $r['user-agent'] );
	}
	return $r;
}

add_filter( 'registration_errors', '__secupress_registration_test_errors', PHP_INT_MAX, 2 );
function __secupress_registration_test_errors( $errors, $sanitized_user_login ) {
	if ( ! $errors->get_error_code() && strpos( $sanitized_user_login, 'secupress' ) !== false ) {
		set_transient( 'secupress_registration_test', 'failed', HOUR_IN_SECONDS );
		$errors->add( 'secupress_registration_test', 'secupress_registration_test_failed' );
	}
	return $errors;
}