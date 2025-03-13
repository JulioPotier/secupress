<?php
/**
 * Module Name: Captcha for Login
 * Description: Add a captcha on the login form
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

// EMERGENCY BYPASS!
if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	return;
}

/**
 * Start a session if needed
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_captcha_session() {
	if ( session_status() === PHP_SESSION_NONE && ! headers_sent() ) {
		session_start( [
			'read_and_close' => true,
		] );
		secupress_update_captcha_seed();
	}
}
secupress_captcha_session();
if ( ! session_id() ) {
	define( 'SECUPRESS_CAPTCHA_NO_SESSION', true );
	return; // No session, the captcha won't work.
}

/**
 * Update our sessions vars if needed
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_update_captcha_seed() {
	$_SESSION['captcha-seed']  = $_SESSION['captcha-seed'] ?? secupress_generate_key();
	$_SESSION['captcha-timer'] = microtime( true );
}

/**
 * Returns a part of a time based md5 hash
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string|int) $seed
 * 
 * @return (string) $md5
 **/
function secupress_captcha_key( $seed = 0 ) {
	return substr( md5( $seed . $_SESSION['captcha-seed'] . secupress_generate_hash( 'captcha' ) ), 2, 8 );
}

/**
 * Tell if the captcha UI should be displayed in the page.
 *
 * @since 1.3
 * @author Grégory Viguier
 * 
 * @return (bool)
 */
function secupress_can_display_captcha() {
	global $pagenow;

	if ( ! is_multisite() ) {
		// Only on the login form and the registration form.
		return ! isset( $_GET['action'] ) || 'login' === $_GET['action'] || 'register' === $_GET['action'];
	}
	if ( is_user_logged_in() || is_super_admin() ) {
		wp_redirect( admin_url() );
		die();
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

add_action( 'login_form',          'secupress_add_captcha_on_login_form' );
add_action( 'register_form',       'secupress_add_captcha_on_login_form' );
add_action( 'signup_extra_fields', 'secupress_add_captcha_on_login_form', 100 );
/**
 * Print the captcha in the login form.
 * 
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
 * 
 * @since 1.4.7 Add filters
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_add_captcha_on_login_form() {
	if ( ! secupress_can_display_captcha() ) {
		return;
	}
	$captcha_title = apply_filters( 'secupress.plugins.login-captcha.title.text', __( 'Human Verification', 'secupress' ) );
	?>
	<div id="secupress-areyouhuman">
		<label><?php echo $captcha_title; ?></label>
	<?php
	$style         = secupress_get_module_option( 'captcha_captcha-style', 'simple', 'users-login' );
	switch ( $style ) {
		case 'simple':
			secupress_add_captcha_on_login_form__simple();
		break;
		
		case 'challenge':
			secupress_add_captcha_on_login_form__challenge();
		break;
		
		default:
			echo 'Error #' . __FUNCTION__; // DO NOT TRANSLATE
		break;
	}
	?>
	</div>
	<?php
}

/**
 * Print the simple captcha in the login form
 * 
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
 */
function secupress_add_captcha_on_login_form__simple() {
	$session_expired = apply_filters( 'secupress.plugins.login-captcha.error.text',   __( 'Too late, please try again.', 'secupress' ) );
	$verif_success   = apply_filters( 'secupress.plugins.login-captcha.success.text', __( 'Verification Successful!', 'secupress' ) );
	$please_wait     = apply_filters( 'secupress.plugins.login-captcha.wait.text',    __( 'Please wait', 'secupress' ) );
	?>
	<div>
		<div id="secupress-areyouhuman-simple">
			<label>
				<span class="secupress-checkme h ide-if-no-js" role="checkbox" tabindex="0" aria-checked="false"></span>
				<i class="secupress-checkme" id="i-secupress-checkme"><?php echo $please_wait; ?></i>
				<i id="i-secupress-checkme-ok"><?php echo $verif_success; ?></i>
				<i id="i-secupress-checkme-ko"><?php echo $session_expired; ?></i>
			</label>
		</div>
		<input type="hidden" name="captcha-timer" value="<?php echo $_SESSION['captcha-timer'] ?? 0; ?>">
		<input type="hidden" name="captcha-key" value="<?php echo secupress_captcha_key( $_SESSION['captcha-timer'] ); ?>" />
	</div>
	<?php
}

/**
 * Print the challenge captcha in the login form
 * 
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
 */
function secupress_add_captcha_on_login_form__challenge() {
	$sets      = secupress_get_emojiset( 'all' );
	$set       = secupress_get_module_option( 'captcha_emoji-set', '', 'users-login' );
	if ( 'random' !== $set ) {
		$ark   = array_keys( $sets );
		$set   = $set && isset( $sets[ $set ] ) ? $set : reset( $ark );
	}
	$ar_texts  = secupress_get_emojiset( $set );
	$ar_emojis = array_combine( array_keys( $ar_texts ), array_fill( 0, 5, '' ) );
	$i         = 0;
	$ar_emojis = secupress_shuffle_assoc( $ar_emojis );
	foreach( $ar_emojis as $_emoji => $dummy ) {
		$seed  = $i ? $i : $_SESSION['captcha-timer'];
		$ar_emojis[ $_emoji ] = secupress_captcha_key( $seed );
		$i++;
	}
	$find_text       = $ar_texts[ array_key_first( $ar_emojis) ];
	$check_the_pic   = sprintf( _x( 'Select the %s.', 'emoji item', 'secupress' ), $find_text );

	$ar_emojis       = secupress_shuffle_assoc( $ar_emojis );
	$i               = 0;

	$session_expired = apply_filters( 'secupress.plugins.login-captcha.error.text', __( 'Too late, please try again.', 'secupress' ) );
	?>
	<div id="secupress-areyouhuman-challenge">
		<div><strong><?php echo $check_the_pic; ?></strong></div>

		<input type="hidden" name="captcha-timer" value="<?php echo $_SESSION['captcha-timer'] ?? 0; ?>">
		<input type="radio"  name="captcha-key" class="secupress-screen-reader-text" id="emoji0" value="0" checked="checked" required aria-labelledby="emoji0-label">
		<label for="emoji0" class="emoji-label" aria-label="🚫"><span class="secupress-pie"></span></label>

		<?php
		foreach ($ar_emojis as $_emoji => $_label ) {
			$i++;
			?>
			<nobr>
				<input type="radio" class="secupress-screen-reader-text" id="emoji<?php echo $i; ?>" name="captcha-key" value="<?php echo $ar_emojis[ $_emoji ]; ?>" required aria-labelledby="emoji<?php echo $i; ?>-label">
				<label for="emoji<?php echo $i; ?>" class="emoji-label" aria-label="<?php echo $_emoji; ?>">
					<?php echo $_emoji; ?>
				</label>
			</nobr>
			<?php
		}
		?>
		<div id="secupress-msg-session"><?php echo $session_expired; ?></div>
	</div>
	<?php
}

add_action( 'login_footer', 'secupress_login_captcha_scripts' );
add_action( 'after_signup_form', 'secupress_login_captcha_scripts' );
/**
 * Enqueue captcha styles and scripts.
 *
 * @since 1.0
 * @author Grégory Viguier
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
}

add_filter( 'authenticate', 'secupress_manage_captcha', SECUPRESS_INT_MAX - 20 );
add_filter( 'registration_errors', 'secupress_manage_captcha', SECUPRESS_INT_MAX - 20 );
add_filter( 'wpmu_validate_user_signup', 'secupress_manage_captcha', SECUPRESS_INT_MAX - 20 );
/**
 * Process the captcha test on user log-in.
 *
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
 * 
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (null|object) $object   (Filter authenticate) (WP_User) if the user is authenticated. (WP_Error) or null otherwise.
 *                                (Filter registration_errors) (WP_Error) with no errors or our error.
 *                                (Filter wpmu_validate_user_signup) (array) of $result or (WP_Error) with our error.
 *
 * @return (null|object)
 */
function secupress_manage_captcha( $object ) {
	static $running = false;

	if ( $running ) {
		return $object;
	}
	$running = true;

	if ( defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' ) ) {
		$running = false;
		return $object;
	}

	// Make sure to process only credentials provided by the login form.
	switch ( current_filter() ) {
		case 'authenticate':
			if ( empty( $_POST['log'] ) ) { // WPCS: CSRF ok.
				$running = false;
				return $object;
			}
		break;
		case 'registration_errors':
			if ( ! isset( $_POST['user_login'], $_POST['user_email'] ) ) { // WPCS: CSRF ok.
				$running = false;
				return $object;
			}
		break;
		case 'wpmu_validate_user_signup':
			if ( ! isset( $_POST['user_name'], $_POST['user_email'], $_POST['stage'] ) || 'validate-user-signup' !== $_POST['stage'] ) { // WPCS: CSRF ok.
				$running = false;
				return $object;
			}
		break;
		default: // Should not happen, if so, just return the given parameter
			$running = false;
			return $object;
		break;
	}

	$fallback_wp_error = new WP_Error( 'authentication_failed', __( '<strong>Error</strong>: The human verification is incorrect.', 'secupress' ), __FUNCTION__ );

	$captcha_key   = $_POST['captcha-key'] ?? ''; // WPCS: CSRF ok.
	$captcha_timer = $_POST['captcha-timer'] ?? false; // WPCS: CSRF ok.
	$hash_equals   = hash_equals( secupress_captcha_key( $captcha_timer ), $captcha_key );
	$real_timer    = (int) ( time() - $captcha_timer );
	$timer_equals  = $real_timer >= 3 && $real_timer <= 60;
	$running       = false;
	session_destroy();
	secupress_captcha_session();
	if ( $hash_equals && $timer_equals ) {
		return $object;
	}
	return $fallback_wp_error;
}


/**
 * Process the captcha test on user registration.
 *
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
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

	$captcha_key  = isset( $_POST['captchemoji'] ) ? $_POST['captchemoji'] : null; // WPCS: CSRF ok.
	if ( hash_equals( secupress_captcha_key( 0 ), $_POST['captchemoji'] ) ) {
		$running = false;
		secupress_update_captcha_seed();
		return $errors;
	}
	$running = false;
	return $fallback_wp_error;
}



/**
 * Process the captcha test on user registration on multisite.
 *
 * @since 2.2.6 Captcha v2 revamp
 * @author Julio Potier
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

	$captcha_key  = isset( $_POST['captchemoji'] ) ? $_POST['captchemoji'] : null; // WPCS: CSRF ok.
	if ( hash_equals( secupress_captcha_key( 0 ), $_POST['captchemoji'] ) ) {
		$running = false;
		secupress_update_captcha_seed();
		return $result;
	}
	$running = false;
	return $fallback_wp_error;

}
