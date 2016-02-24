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

function secupress_add_captcha_on_login_form( $echo = false ) {
	?>
	<div>
		<div id="areyouhuman">
			<label>
				<span class="checkme" role="checkbox" tabindex="0" aria-checked="false"></span>
				<i class="checkme"><?php _e( 'Yes, I\'m a Human.', 'secupress' ); ?></i>
			</label>
		</div>
		<div id="msg" class="hidden"><?php _e( 'Session expired, please try again.', 'secupress' ); ?></div>
		<input type="hidden" name="captcha_key" id="captcha_key" value="" />
	</div>
	<?php
}


add_action( 'login_head', 'secupress_login_captcha_scripts' );

function secupress_login_captcha_scripts() {
	if ( isset( $_GET['action'] ) && 'login' !== $_GET['action'] ) {
		return;
	}

	$is_debug = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG;
	$ver      = $is_debug ? time() : SECUPRESS_VERSION;
	$min      = $is_debug ? ''     : '.min';
	$url      = SECUPRESS_INC_URL . 'modules/users-login/plugins/inc/';

	wp_enqueue_style( 'secupress-captcha', $url . 'css/captcha' . $min . '.css', array(), $ver, 'all' );
	wp_print_styles( 'secupress-captcha' );

	wp_enqueue_script( 'secupress-captcha', $url . 'js/captcha' . $min . '.js', array( 'jquery' ), $ver, true );
	wp_localize_script( 'secupress-captcha', 'spCaptchaL10n', array( 'ajaxurl' => esc_url( admin_url( 'admin-ajax.php' ) ), ) );
}


add_action( 'wp_ajax_captcha_check',        'secupress_captcha_check' );
add_action( 'wp_ajax_nopriv_captcha_check', 'secupress_captcha_check' );

function secupress_captcha_check() {
	if ( ! empty( $_POST['captcha_key'] ) || ! isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) || 'XMLHttpRequest' !== $_SERVER['HTTP_X_REQUESTED_WITH'] ) { // a "real" ajax request
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

function secupress_manage_captcha( $raw_user, $username ) {
	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		return $raw_user;
	}

	if ( is_wp_error( $raw_user ) || ! isset( $_POST['log'], $_POST['pwd'] ) ) {
		return $raw_user;
	}

	$captcha_key  = isset( $_POST['captcha_key'] ) ? $_POST['captcha_key'] : null;
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );

	if ( ! isset( $captcha_keys[ $captcha_key ] ) ||
		time() > $captcha_keys[ $captcha_key ] + 2 * MINUTE_IN_SECONDS ||
		time() < $captcha_keys[ $captcha_key ] + 2
	) {
		return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: The Human verification is incorrect.', 'secupress' ) );
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

function secupress_login_form_nojs_error( $message ) {
	if ( ! isset( $_GET['action'] ) || 'login' === $_GET['action'] ) {
		$message .= '<noscript><p class="message">' . __( 'You need to enable JavaScript to send this form correctly.', 'secupress' ) . '</p></noscript>';
	}
	return $message;
}


/**
 * Add the option(s) we use in this plugin to be autoloaded on multisite.
 *
 * @since 1.0
 *
 * @param (array) $option_names An array of network option names.
 *
 * @return (array)
 */
add_filter( '_secupress.options.load_plugins_network_options', 'secupress_captcha_autoload_options' );

function secupress_captcha_autoload_options( $option_names ) {
	$option_names[] = 'secupress_captcha_keys';
	return $option_names;
}
