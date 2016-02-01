<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function __secupress_users_login_settings_callback( $settings ) {
	$modulenow    = 'users-login';
	$settings     = $settings ? $settings : array();
	$old_settings = get_site_option( "secupress_{$modulenow}_settings" );

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Double authentication
	__secupress_double_auth_settings_callback( $modulenow, $settings );

	// Captcha
	__secupress_captcha_settings_callback( $modulenow, $settings );

	// Login protection
	__secupress_login_protection_settings_callback( $modulenow, $settings );

	// Password Policy
	__secupress_password_policy_settings_callback( $modulenow, $settings );

	// Logins blacklist
	__secupress_logins_blacklist_settings_callback( $modulenow, $settings );

	// Move Login
	__secupress_move_login_settings_callback( $modulenow, $settings, $old_settings );

	return $settings;
}


/**
 * (De)Activate double authentication plugins.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_double_auth_settings_callback( $modulenow, &$settings ) {
	if ( ! empty( $settings['double-auth_type'] ) ) {
		secupress_manage_submodule( $modulenow, 'passwordless', '_passwordless' === $settings['double-auth_type'] && secupress_is_pro() );
		secupress_manage_submodule( $modulenow, 'googleauth',   'googleauth'    === $settings['double-auth_type'] );
		secupress_manage_submodule( $modulenow, 'emaillink',    'emaillink'     === $settings['double-auth_type'] );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'passwordless', 'googleauth', 'emaillink' ) );
	}

	unset( $settings['double-auth_type'] );

	secupress_manage_affected_roles( $settings, 'double-auth' );
}


/**
 * (De)Activate captcha plugin.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_captcha_settings_callback( $modulenow, &$settings ) {
	secupress_manage_submodule( $modulenow, 'login-captcha', ! empty( $settings['captcha_activate'] ) );
	unset( $settings['captcha_activate'] );
}


/**
 * (De)Activate login protection plugin and sanitize settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_login_protection_settings_callback( $modulenow, &$settings ) {
	if ( ! empty( $settings['login-protection_type'] ) ) {
		$settings['login-protection_type'] = array_flip( $settings['login-protection_type'] );

		secupress_manage_submodule( $modulenow, 'limitloginattempts', isset( $settings['login-protection_type']['limitloginattempts'] ) );
		secupress_manage_submodule( $modulenow, 'bannonexistsuser',   isset( $settings['login-protection_type']['bannonexistsuser']   ) );
		secupress_manage_submodule( $modulenow, 'nonlogintimeslot',   isset( $settings['login-protection_type']['nonlogintimeslot']   ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	$settings['login-protection_number_attempts']  = ! empty( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']         = ! empty( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'], 1, 60, 5 )         : 5;
	$settings['login-protection_nonlogintimeslot'] = ! empty( $settings['login-protection_nonlogintimeslot'] ) && is_array( $settings['login-protection_nonlogintimeslot'] ) ? $settings['login-protection_nonlogintimeslot'] : array();

	$settings['login-protection_nonlogintimeslot']['from_hour']   = ! empty( $settings['login-protection_nonlogintimeslot']['from_hour'] )   ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['from_hour'], 0, 23, 0 )   : 0;
	$settings['login-protection_nonlogintimeslot']['from_minute'] = ! empty( $settings['login-protection_nonlogintimeslot']['from_minute'] ) ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['from_minute'], 0, 59, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['to_hour']     = ! empty( $settings['login-protection_nonlogintimeslot']['to_hour'] )     ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['to_hour'], 0, 23, 0 )     : 0;
	$settings['login-protection_nonlogintimeslot']['to_minute']   = ! empty( $settings['login-protection_nonlogintimeslot']['to_minute'] )   ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['to_minute'], 0, 59, 0 )   : 0;

	secupress_manage_submodule( $modulenow, 'only-one-connexion', ! empty( $settings['login-protection_only-one-connexion'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow, 'sessions-control',   ! empty( $settings['login-protection_sessions_control'] ) && secupress_is_pro() );

	unset( $settings['login-protection_type'], $settings['login-protection_only-one-connexion'], $settings['login-protection_sessions_control'] );
}


/**
 * (De)Activate password policy plugins and sanitize settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_password_policy_settings_callback( $modulenow, &$settings ) {
	if ( secupress_is_pro() ) {
		$settings['password-policy_password_expiration'] = ! empty( $settings['password-policy_password_expiration'] ) ? absint( $settings['password-policy_password_expiration'] ) : 0;
		secupress_manage_submodule( $modulenow, 'password-expiration', $settings['password-policy_password_expiration'] > 0 );
		secupress_manage_submodule( $modulenow, 'strong-passwords', ! empty( $settings['password-policy_strong_passwords'] ) );
	} else {
		$settings['password-policy_password_expiration'] = 0;
		secupress_deactivate_submodule( $modulenow, array( 'password-expiration', 'strong-passwords' ) );
	}

	unset( $settings['password-policy_strong_passwords'] );

	secupress_manage_affected_roles( $settings, 'password-policy' );
}


/**
 * (De)Activate logins blacklist plugin.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_logins_blacklist_settings_callback( $modulenow, &$settings ) {
	secupress_manage_submodule( $modulenow, 'blacklist-logins', ! empty( $settings['blacklist-logins_activated'] ) );
	unset( $settings['blacklist-logins_activated'] );
}


/**
 * (De)Activate Move Login plugin. Sanitize and validate settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow    Current module.
 * @param (array)  $settings     The module settings, passed by reference.
 * @param (array)  $old_settings The module previous settings.
 */
function __secupress_move_login_settings_callback( $modulenow, &$settings, $old_settings ) {
	// Slugs.
	$slugs     = secupress_move_login_slug_labels();
	// Handle forbidden slugs and duplicates.
	$errors    = array( 'forbidden' => array(), 'duplicates' => array() );
	// `postpass`, `retrievepassword` and `rp` are forbidden if they are not customizable.
	$forbidden = array( 'postpass' => 1, 'retrievepassword' => 1, 'rp' => 1 );
	$forbidden = array_diff_key( $forbidden, $slugs );
	$dones     = array();

	foreach ( $slugs as $default_slug => $label ) {
		$option_name = 'move-login_slug-' . $default_slug;

		// Build a fallback slug. Try the old value first.
		$fallback_slug = ! empty( $old_settings[ $option_name ] ) ? sanitize_title( $old_settings[ $option_name ] ) : '';
		// Then fallback to the default value.
		if ( ! $fallback_slug || isset( $forbidden[ $fallback_slug ] ) || isset( $dones[ $fallback_slug ] ) ) {
			$fallback_slug = $default_slug;
		}
		// Last chance, add an increment.
		if ( isset( $forbidden[ $fallback_slug ] ) || isset( $dones[ $fallback_slug ] ) ) {
			$i = 1;
			while ( isset( $forbidden[ $fallback_slug . $i ] ) || isset( $dones[ $fallback_slug . $i ] ) ) {
				++$i;
			}
			$fallback_slug .= $i;
		}

		// Sanitize the value provided.
		$new_slug = ! empty( $settings[ $option_name ] ) ? sanitize_title( $settings[ $option_name ] ) : '';

		if ( ! $new_slug ) {
			// Sanitization did its job til the end, or the field was empty.
			$new_slug = $fallback_slug;
		} else {
			// Validation.
			// Test for forbidden slugs.
			if ( isset( $forbidden[ $new_slug ] ) ) {
				$errors['forbidden'][] = $new_slug;
				$new_slug = $fallback_slug;
			}
			// Test for duplicates.
			elseif ( isset( $dones[ $new_slug ] ) ) {
				$errors['duplicates'][] = $new_slug;
				$new_slug = $fallback_slug;
			}
		}

		$dones[ $new_slug ]       = 1;
		$settings[ $option_name ] = $new_slug;
	}

	// Access to `wp-login.php`.
	$wp_login_actions = secupress_move_login_login_access_labels();
	$settings['move-login_login-access'] = isset( $settings['move-login_login-access'], $wp_login_actions[ $settings['move-login_login-access'] ] ) ? $settings['move-login_login-access'] : 'error';

	// Access to `wp-admin`.
	$admin_actions = secupress_move_login_login_redirect_labels();
	$settings['move-login_login-redirect'] = isset( $settings['move-login_login-redirect'], $wp_login_actions[ $settings['move-login_login-redirect'] ] ) ? $settings['move-login_login-redirect'] : 'redir-login';

	// Handle validation errors.
	$errors['forbidden']  = array_unique( $errors['forbidden'] );
	$errors['duplicates'] = array_unique( $errors['duplicates'] );

	if ( $nbr_forbidden = count( $errors['forbidden'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= sprintf( _n( 'The slug %s is forbidden.', 'The slugs %s are forbidden.', $nbr_forbidden, 'secupress' ), wp_sprintf( '<code>%l</code>', $errors['forbidden'] ) );
		add_settings_error( "secupress_{$modulenow}_settings", 'forbidden-slugs', $message, 'error' );
	}
	if ( ! empty( $errors['duplicates'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'The links can\'t have the same slugs.', 'secupress' );
		add_settings_error( "secupress_{$modulenow}_settings", 'duplicate-slugs', $message, 'error' );
	}

	// Activate or deactivate plugin.
	secupress_manage_submodule( $modulenow, 'move-login', ! empty( $settings['move-login_activated'] ) );
	unset( $settings['move-login_activated'] );
}


/*------------------------------------------------------------------------------------------------*/
/* NOTICES ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Display a notice if the standalone version of Move Login is used.
 *
 * @since 1.0
 *
 * @param (array) $plugins A list of plugin paths, relative to the plugins folder.
 */
add_filter( 'secupress.plugins.packed-plugins', 'secupress_move_login_add_packed_plugin' );

function secupress_move_login_add_packed_plugin( $plugins ) {
	$plugins['move-login'] = 'sf-move-login/sf-move-login.php';
	return $plugins;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

/*
 * Create default option on install.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */

add_action( 'wp_secupress_first_install', '__secupress_install_users_login_module' );

function __secupress_install_users_login_module( $module ) {
	if ( 'all' === $module || 'users-login' === $module ) {
		$values = array(
			'double-auth_type' => '-1',
			//// pas fini
		);
		secupress_update_module_options( $values, 'users-login' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DEFAULT VALUES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Move Login: return the list of customizable login actions.
 *
 * @since 1.0
 *
 * @return (array) Return an array with the action names as keys and field labels as values.
 */
function secupress_move_login_slug_labels() {
	$labels = array(
		'login'        => __( 'Log in' ),
		'logout'       => __( 'Log out' ),
		'register'     => __( 'Register' ),
		'lostpassword' => __( 'Lost Password' ),
		'resetpass'    => __( 'Password Reset' ),
	);

	/**
	 * Add custom actions to the list of customizable actions.
	 *
	 * @since 1.0
	 *
	 * @param (array) An array with the action names as keys and field labels as values.
	*/
	$new_slugs = apply_filters( 'sfml_additional_slugs', array() );

	if ( $new_slugs && is_array( $new_slugs ) ) {
		$new_slugs = array_diff_key( $new_slugs, $labels );
		$labels    = array_merge( $labels, $new_slugs );
	}

	return $labels;
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Move Login: return the list of available actions to perform when someone reaches the old login page.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_move_login_login_access_labels() {
	return array(
		'error'      => __( 'Display an error message', 'secupress' ),
		'redir_404'  => __( 'Redirect to a "Page not found" error page', 'secupress' ),
		'redir_home' => __( 'Redirect to the home page', 'secupress' ),
	);
}


/*
 * Move Login: return the list of available actions to perform when a logged out user reaches the administration area.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_move_login_login_redirect_labels() {
	return array(
		'redir-login' => __( 'Do nothing, redirect to the new login page', 'secupress' ) . ' <span class="description">(' . __( 'not recommended', 'secupress' ) . ')</span>',
		'error'       => __( 'Display an error message', 'secupress' ),
		'redir_404'   => __( 'Redirect to a "Page not found" error page', 'secupress' ),
		'redir_home'  => __( 'Redirect to the home page', 'secupress' ),
	);
}
