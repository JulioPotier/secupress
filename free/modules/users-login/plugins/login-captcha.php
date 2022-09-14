<?php
/**
 * Module Name: Captcha for Login
 * Description: Add a gentle captcha on the login form
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.0.3
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


// EMERGENCY BYPASS!
if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	return;
}

add_action( 'login_form',          'secupress_add_captcha_on_login_form' );
add_action( 'register_form',       'secupress_add_captcha_on_login_form' );
add_action( 'signup_extra_fields', 'secupress_add_captcha_on_login_form', 100 );
/**
 * Print the captcha in the login form.
 *
 * @author Grégory Viguier
 * @since 1.4.7 Add filters
 * @since 1.0
 */
function secupress_add_captcha_on_login_form() {
	if ( ! secupress_can_display_captcha() ) {
		return;
	}
	/**
	 * This filter is documented in wp-signup.php.
	 * @param (string) The text to be clicked next to the checkbox
	 */
	$yes_im_a_human  = apply_filters( 'secupress.plugins.login-captcha.checkbox.text', __( 'Yes, I’m a human.', 'secupress' ) );
	$session_expired = apply_filters( 'secupress.plugins.login-captcha.error.text', __( 'Session expired, please try again.', 'secupress' ) );
	?>
	<div>
		<div id="areyouhuman">
			<label>
				<span class="checkme" role="checkbox" tabindex="0" aria-checked="false"></span>
				<i class="checkme"><?php echo $yes_im_a_human; ?></i>
			</label>
		</div>
		<div id="msg" class="hidden"><?php echo $session_expired; ?></div>
		<input type="hidden" name="captcha_key" id="captcha_key" value="" />
	</div>
	<?php
}


add_action( 'login_footer',    'secupress_login_captcha_scripts' );
add_action( 'after_signup_form', 'secupress_login_captcha_scripts' );
/**
 * Enqueue captcha styles and scripts.
 *
 * @since 1.0
 */
function secupress_login_captcha_scripts() {
	if ( ! secupress_can_display_captcha() ) {
		return;
	}

	$is_debug = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG;
	$ver      = $is_debug ? time() : SECUPRESS_VERSION;
	$min      = $is_debug ? ''     : '.min';
	$url      = SECUPRESS_FREE_URL . 'modules/users-login/plugins/inc/';

	wp_enqueue_style( 'secupress-captcha', $url . 'css/captcha' . $min . '.css', array(), $ver, 'all' );
	wp_print_styles( 'secupress-captcha' );

	wp_enqueue_script( 'secupress-captcha', $url . 'js/captcha' . $min . '.js', array( 'jquery' ), $ver, true );
	wp_localize_script( 'secupress-captcha', 'spCaptchaL10n', array(
		'ajaxurl'  => esc_url( admin_url( 'admin-ajax.php' ) ),
		'hPotText' => __( 'Do not fill in this field.', 'secupress' ),
	) );
	wp_print_scripts( 'secupress-captcha' );
}


add_action( 'wp_ajax_captcha_check',        'secupress_captcha_check' );
add_action( 'wp_ajax_nopriv_captcha_check', 'secupress_captcha_check' );
/**
 * Check the captcha via ajax.
 *
 * @since 1.0
 */
function secupress_captcha_check() {
	if ( ! empty( $_POST['captcha_key'] ) || ! isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) || 'XMLHttpRequest' !== $_SERVER['HTTP_X_REQUESTED_WITH'] ) { // WPCS: CSRF ok. A "real" ajax request.
		if ( ! headers_sent() ) {
			status_header( 400 );
		}
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


add_action( 'authenticate', 'secupress_manage_captcha', SECUPRESS_INT_MAX - 20, 2 );
/**
 * Process the captcha test on user log-in.
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
	static $running = false;

	if ( $running ) {
		return $raw_user;
	}
	$running = true;

	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		$running = false;
		return $raw_user;
	}

	// Make sure to process only credentials provided by the login form.
	if ( empty( $_POST['log'] ) ) { // WPCS: CSRF ok.
		$running = false;
		return $raw_user;
	}

	$fallback_wp_error = new WP_Error( 'authentication_failed', __( '<strong>Error</strong>: The human verification is incorrect.', 'secupress' ), __FUNCTION__ );

	$captcha_key  = isset( $_POST['captcha_key'] ) ? $_POST['captcha_key'] : null; // WPCS: CSRF ok.
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );

	if ( ! isset( $captcha_keys[ $captcha_key ] ) ||
		time() > $captcha_keys[ $captcha_key ] + 2 * MINUTE_IN_SECONDS ||
		time() < $captcha_keys[ $captcha_key ] + 2
	) {
		$running = false;
		return $fallback_wp_error;
	}

	unset( $captcha_keys[ $captcha_key ] );

	delete_site_option( 'secupress_captcha_keys' );
	add_site_option( 'secupress_captcha_keys', $captcha_keys, false );

	$running = false;
	return $raw_user;
}


add_filter( 'registration_errors', 'secupress_manage_registration_captcha', SECUPRESS_INT_MAX - 20 );
/**
 * Process the captcha test on user registration.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (object) $errors A WP_Error object containing any errors encountered during registration.
 *
 * @return (object) The WP_Error object.
 */
function secupress_manage_registration_captcha( $errors ) {
	static $running = false;

	if ( $running ) {
		return $errors;
	}
	$running = true;

	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		$running = false;
		return $errors;
	}

	// Make sure to process only credentials provided by the registration form.
	if ( ! isset( $_POST['user_login'], $_POST['user_email'] ) ) { // WPCS: CSRF ok.
		$running = false;
		return $errors;
	}

	$captcha_key  = isset( $_POST['captcha_key'] ) ? $_POST['captcha_key'] : null; // WPCS: CSRF ok.
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );

	if ( ! isset( $captcha_keys[ $captcha_key ] ) ||
		time() > $captcha_keys[ $captcha_key ] + 2 * MINUTE_IN_SECONDS ||
		time() < $captcha_keys[ $captcha_key ] + 2
	) {
		$errors->add( 'authentication_failed', __( '<strong>Error</strong>: The human verification is incorrect.', 'secupress' ), __FUNCTION__ );
		$running = false;
		return $errors;
	}

	unset( $captcha_keys[ $captcha_key ] );

	if ( ! secupress_wp_version_is( '4.2.0-alpha' ) ) {
		delete_site_option( 'secupress_captcha_keys' );
		add_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	} else {
		update_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	}

	$running = false;
	return $errors;
}


add_filter( 'wpmu_validate_user_signup', 'secupress_manage_ms_registration_captcha', SECUPRESS_INT_MAX - 20 );
/**
 * Process the captcha test on user registration on multisite.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (array) $result The array of user name, email and the error messages:
 *                        (string) $user_name     Sanitized and unique username.
 *                        (string) $orig_username Original username.
 *                        (string) $user_email    User email address.
 *                        (object) $errors        WP_Error object containing any errors found.
 */
function secupress_manage_ms_registration_captcha( $result ) {
	static $running = false;

	if ( $running ) {
		return $result;
	}
	$running = true;

	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		$running = false;
		return $result;
	}

	// Make sure to process only credentials provided by the registration form.
	if ( ! isset( $_POST['user_name'], $_POST['user_email'], $_POST['stage'] ) || 'validate-user-signup' !== $_POST['stage'] ) { // WPCS: CSRF ok.
		$running = false;
		return $result;
	}

	$captcha_key  = isset( $_POST['captcha_key'] ) ? $_POST['captcha_key'] : null; // WPCS: CSRF ok.
	$captcha_keys = get_site_option( 'secupress_captcha_keys', array() );

	if ( ! isset( $captcha_keys[ $captcha_key ] ) ||
		time() > $captcha_keys[ $captcha_key ] + 2 * MINUTE_IN_SECONDS ||
		time() < $captcha_keys[ $captcha_key ] + 2
	) {
		$result['errors']->add( 'authentication_failed', __( '<strong>Error</strong>: The human verification is incorrect.', 'secupress' ), __FUNCTION__ );
		$running = false;
		return $result;
	}

	unset( $captcha_keys[ $captcha_key ] );

	if ( ! secupress_wp_version_is( '4.2.0-alpha' ) ) {
		delete_site_option( 'secupress_captcha_keys' );
		add_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	} else {
		update_site_option( 'secupress_captcha_keys', $captcha_keys, false );
	}

	$running = false;
	return $result;
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
	if ( secupress_can_display_captcha() ) {
		$message .= '<noscript><p class="message">' . __( 'You need to enable JavaScript to send this form correctly.', 'secupress' ) . '</p></noscript>';
	}
	return $message;
}


add_action( 'signup_extra_fields', 'secupress_print_login_form_nojs_error', 1 );
/**
 * On multisite, print the "The human verification is incorrect" message and a message when the user disabled JavaScript on his/her browser.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (array) $errors An array possibly containing 'user_name' or 'user_email' errors.
 */
function secupress_print_login_form_nojs_error( $errors ) {
	if ( $errmsg = $errors->get_error_message( 'authentication_failed' ) ) {
		echo '<p class="error">' . $errmsg . '</p>';
	}

	if ( secupress_can_display_captcha() ) {
		echo '<noscript><p class="error">' . __( 'You need to enable JavaScript to send this form correctly.', 'secupress' ) . '</p></noscript>';
	}
}


/**
 * Tell if the captcha UI should be displayed in the page.
 *
 * @since 1.3
 *
 * @return (bool)
 */
function secupress_can_display_captcha() {
	global $pagenow;

	if ( ! is_multisite() ) {
		// Only on the login form and the registration form.
		return ! isset( $_GET['action'] ) || 'login' === $_GET['action'] || 'register' === $_GET['action'];
	}

	if ( is_super_admin() ) {
		// Network admins have a free pass.
		return false;
	}

	if ( is_user_logged_in() ) {
		// Logged in users don't see the form.
		return false;
	}

	if ( 'wp-signup.php' !== $pagenow ) {
		// Login page, only on the login form.
		return ! isset( $_GET['action'] ) || 'login' === $_GET['action'];
	}

	// Registrations page.
	$active_signup = get_site_option( 'registration', 'none' );
	/**
	 * This filter is documented in wp-signup.php.
	 * Possible values are 'none', 'user', 'blog' and 'all'.
	 */
	$active_signup = apply_filters( 'wpmu_active_signup', $active_signup );

	switch ( $active_signup ) {
		case 'user':
		case 'all':
			// Deal only with the "user" form.
			return true;
		default:
			return false;
	}
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
