<?php
/*
Module Name: Captcha for Login
Description: Add a gentle captcha on the login form
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'login_form', 'secupress_add_captcha_on_login_form' );
/**
 * Print the captcha in the login form.
 *
 * @since 1.0
 */
function secupress_add_captcha_on_login_form() {
	?>
	<div>
		<div id="areyouhuman">
			<label>
				<span class="checkme" role="checkbox" tabindex="0" aria-checked="false"></span>
				<i class="checkme"><?php _e( 'Yes, I\'m a human.', 'secupress' ); ?></i>
			</label>
		</div>
		<div id="msg" class="hidden"><?php _e( 'Session expired, please try again.', 'secupress' ); ?></div>
		<input type="hidden" name="captcha_key" id="captcha_key" value="" />
	</div>
	<?php
}


add_action( 'login_head', 'secupress_login_captcha_scripts' );
/**
 * Enqueue captcha styles and scripts.
 *
 * @since 1.0
 */
function secupress_login_captcha_scripts() {
	if ( isset( $_GET['action'] ) && 'login' !== $_GET['action'] && 'notpasswordless' !== $_GET['action'] ) {
		return;
	}

	$is_debug = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG;
	$ver      = $is_debug ? time() : SECUPRESS_VERSION;
	$min      = $is_debug ? ''     : '.min';
	$url      = SECUPRESS_INC_URL . 'modules/users-login/plugins/inc/';

	wp_enqueue_style( 'secupress-captcha', $url . 'css/captcha' . $min . '.css', array(), $ver, 'all' );
	wp_print_styles( 'secupress-captcha' );

	wp_enqueue_script( 'secupress-captcha', $url . 'js/captcha' . $min . '.js', array( 'jquery' ), $ver, true );
	wp_localize_script( 'secupress-captcha', 'spCaptchaL10n', array(
		'ajaxurl'  => esc_url( admin_url( 'admin-ajax.php' ) ),
		'hPotText' => __( 'Do not fill in this field.', 'secupress' ),
	) );
}


add_action( 'wp_ajax_captcha_check',        'secupress_captcha_check' );
add_action( 'wp_ajax_nopriv_captcha_check', 'secupress_captcha_check' );
/**
 * Check the captcha.
 *
 * @since 1.0
 */
function secupress_captcha_check() {
	if ( ! empty( $_POST['captcha_key'] ) || ! isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) || 'XMLHttpRequest' !== $_SERVER['HTTP_X_REQUESTED_WITH'] ) { // WPCS: CSRF ok. A "real" ajax request.
		status_header( 400 );
		wp_send_json_error();
	}

	$t            = time();
	$token        = wp_generate_password( 12, false );
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );
	$captcha_keys[ $token ] = $t;

	foreach ( $captcha_keys as $key => $value ) {
		if ( $t > $value ) {
			unset( $captcha_keys[ $key ] );
		}
	}

	if ( ! secupress_wp_version_is( '4.2.0-alpha' ) ) {
		delete_site_option( 'secupress_captcha_keys' );
		add_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	} else {
		update_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	}

	wp_send_json_success( $token );
}


add_action( 'authenticate', 'secupress_manage_captcha', 20, 2 );
/**
 * Display a message when the user disabled JavaScript on his/her browser.
 *
 * @since 1.0
 *
 * @param (null|object) $raw_user WP_User if the user is authenticated.
 *                                WP_Error or null otherwise.
 * @param (string)      $username Username or email address.
 *
 * @return (null|object)
 */
function secupress_manage_captcha( $raw_user, $username ) {
	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		return $raw_user;
	}

	if ( is_wp_error( $raw_user ) || ! isset( $_POST['log'], $_POST['pwd'] ) ) { // WPCS: CSRF ok.
		return $raw_user;
	}

	$fallback_wp_error = new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: The human verification is incorrect.', 'secupress' ), __FUNCTION__ );

	if ( ! isset( $_POST['sp_name'] ) || '' !== $_POST['sp_name'] ) { // WPCS: CSRF ok.
		return $fallback_wp_error;
	}

	$captcha_key  = isset( $_POST['captcha_key'] ) ? $_POST['captcha_key'] : null; // WPCS: CSRF ok.
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );

	if ( ! isset( $captcha_keys[ $captcha_key ] ) ||
		time() > $captcha_keys[ $captcha_key ] + 2 * MINUTE_IN_SECONDS ||
		time() < $captcha_keys[ $captcha_key ] + 2
	) {
		return $fallback_wp_error;
	}

	unset( $captcha_keys[ $captcha_key ] );

	if ( ! secupress_wp_version_is( '4.2.0-alpha' ) ) {
		delete_site_option( 'secupress_captcha_keys' );
		add_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	} else {
		update_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	}

	return $raw_user;
}


add_filter( 'login_message', 'secupress_login_form_nojs_error' );
/**
 * Display a message when the user disabled JavaScript on his/her browser.
 *
 * @since 1.0
 *
 * @param (string) $message Messages.
 *
 * @return (string)
 */
function secupress_login_form_nojs_error( $message ) {
	if ( ! isset( $_GET['action'] ) || 'login' === $_GET['action'] ) {
		$message .= '<noscript><p class="message">' . __( 'You need to enable JavaScript to send this form correctly.', 'secupress' ) . '</p></noscript>';
	}
	return $message;
}


add_filter( 'secupress.options.load_plugins_network_options', 'secupress_captcha_autoload_options' );
/**
 * Add the option(s) we use in this plugin to be autoloaded on multisite.
 *
 * @since 1.0
 *
 * @param (array) $option_names An array of network option names.
 *
 * @return (array)
 */
function secupress_captcha_autoload_options( $option_names ) {
	$option_names[] = 'secupress_captcha_keys';
	return $option_names;
}
