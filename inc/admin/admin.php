<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_post_secupress_fixit', '__secupress_fixit_ajax' );
add_action( 'wp_ajax_secupress_fixit', '__secupress_fixit_ajax' );
function __secupress_fixit_ajax( $test_name = null ) {

	$test_name = isset( $_GET['test'] ) ? $_GET['test'] : $test_name;
	$nonce = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce'] : 0;
	$nonce = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_fixit_' . $test_name );

	if ( ! empty( $test_name ) && $nonce &&
		file_exists( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan-' . secupress_class_name( $test_name ) . '.php' )
		) {

		require_once( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan.php' );
		include_once( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan-' . secupress_class_name( $test_name ) . '.php' );

		$classname = 'SecuPress_Scan_' . $test_name;
		if ( class_exists( $classname ) ) {
			ob_start();
				@set_time_limit( 0 );
				$secupress_scan = $classname::get_instance();;
				$response = $secupress_scan->fix();
			ob_end_flush();
		}

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_success( $response );
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

add_action( 'admin_post_secupress_scanner', '__secupress_scanner_ajax' );
add_action( 'wp_ajax_secupress_scanner', '__secupress_scanner_ajax' );
function __secupress_scanner_ajax( $test_name = null ) {

	$test_name = isset( $_GET['test'] ) ? $_GET['test'] : $test_name;
	$nonce = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce'] : 0;
	$nonce = 0 === $nonce || wp_verify_nonce( $nonce, 'secupress_scanner_' . $test_name );


	if ( ! empty( $test_name ) && $nonce &&
		file_exists( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan-' . secupress_class_name( $test_name ) . '.php' )
		) {

		require_once( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan.php' );
		include_once( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan-' . secupress_class_name( $test_name ) . '.php' );
		$classname = 'SecuPress_Scan_' . $test_name;
		if ( class_exists( $classname ) ) {
			ob_start();
				@set_time_limit( 0 );
				$secupress_scan = $classname::get_instance();
				$response = $secupress_scan->scan();
			ob_end_flush();
		}

		$output = array();
		$output[ $test_name ]['status'] = secupress_status( $response['status'] );
		$output[ $test_name ]['class']  = sanitize_key( $response['status'] );
		$output[ $test_name ]['message'] = '';

		$messages = $secupress_scan->get_messages();
		foreach ( $response['msgs'] as $id => $atts ) {
			if ( is_array( $messages[ $id ] ) ) {
				$count  = array_shift( $atts );
				$string = translate_nooped_plural( $messages[ $id ], $count );
			} else {
				$string = $messages[ $id ];
			}
			$output[ $test_name ]['message'] .= ! empty( $atts ) ? vsprintf( $string, $atts ) : $messages[ $id ];
			$output[ $test_name ]['message'] .= '<br>';
		}

		$times = (array) get_option( SECUPRESS_SCAN_TIMES );
		$counts = secupress_get_scanner_counts();
		$percent = floor( $counts['good'] * 100 / $counts['total'] );
		$times[] = array( 'grade' => $counts['grade'], 'percent' => $percent, 'time' => time() );
		$times = array_filter( array_slice( $times , -5 ) );
		update_option( SECUPRESS_SCAN_TIMES, $times );

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_success( $output );
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
add_action( 'admin_print_styles-' . SECUPRESS_PLUGIN_SLUG . '_page_secupress_scanner', '__secupress_scanner_add_admin_css_js' ); //// dédoublonner

function __secupress_scanner_add_admin_css_js() {
	$suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';

	wp_enqueue_style( 'secupress-scanner-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-scanner.css', null, SECUPRESS_VERSION );

	wp_enqueue_script( 'secupress-scanner-js', SECUPRESS_ADMIN_JS_URL . 'secupress-scanner.js', null, SECUPRESS_VERSION, true );
	wp_enqueue_script( 'secupress-chartjs',    SECUPRESS_ADMIN_JS_URL . 'Chart' . $suffix . '.js', null, '1.0.2.1', true );
	wp_enqueue_script( 'jquery-timeago',       SECUPRESS_ADMIN_JS_URL . 'jquery.timeago.js', null, '1.4.1', true );

	$counts = secupress_get_scanner_counts();
	wp_localize_script( 'secupress-chartjs', 'SecuPressi18nChart',
		array(
			'good'          => array( 'value' => $counts['good'],          'text' => __( 'Good', 'secupress' ) ),
			'warning'       => array( 'value' => $counts['warning'],       'text' => __( 'Warning', 'secupress' ) ),
			'bad'           => array( 'value' => $counts['bad'],           'text' => __( 'Bad', 'secupress' ) ),
			'notscannedyet' => array( 'value' => $counts['notscannedyet'], 'text' => __( 'Not Scanned Yet', 'secupress' ) ),
		)
	);
}

/**
 * Add the CSS and JS files for SecuPress settings page
 *
 * @since 1.0
 */
add_action( 'admin_print_styles-' . SECUPRESS_PLUGIN_SLUG . '_page_secupress_settings', '__secupress_settings_add_admin_css', 99999 );

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
add_action( 'admin_print_scripts-' . SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules', '__secupress_modules_add_admin_js' );

function __secupress_modules_add_admin_js() {
	wp_enqueue_script( 'secupress-zxcvbn-async', includes_url( '/js/zxcvbn.min.js' ), array( 'jquery' ) );
	wp_enqueue_script( 'secupress-modules-js', SECUPRESS_ADMIN_JS_URL . 'secupress-modules.js', array( 'jquery', 'secupress-zxcvbn-async', 'password-strength-meter' ), SECUPRESS_VERSION, true );

	wp_localize_script( 'secupress-modules-js', 'l10nmodules', array( 'selectOneRoleMinimum' => __( 'Select 1 role minimum', 'secupress' ) ) );
	wp_localize_script( 'password-strength-meter', 'pwsL10n', array(
		'empty'    => __( 'Enter a password', 'secupress' ),
		'short'    => __( 'Very weak' ),
		'bad'      => __( 'Weak' ),
		'good'     => _x( 'Medium', 'password strength' ),
		'strong'   => __( 'Strong' ),
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
	if ( secupress_is_white_label() ) {
		// We change the plugin's header
		$plugins[ SECUPRESS_PLUGIN_FILE ] = array(
				'Name'			=> secupress_get_option( 'wl_plugin_name' ),
				'PluginURI'		=> secupress_get_option( 'wl_plugin_URI' ),
				'Version'		=> isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] : '',
				'Description'	=> reset( ( secupress_get_option( 'wl_description', array() ) ) ),
				'Author'		=> secupress_get_option( 'wl_author' ),
				'AuthorURI'		=> secupress_get_option( 'wl_author_URI' ),
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
	$gz = 'gz' . strrev( 'etalfed' );
	$options = $gz//;
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