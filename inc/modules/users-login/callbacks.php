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
function secupress_users_login_settings_callback( $settings ) {
	$modulenow = 'users-login';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Double authentication.
	secupress_double_auth_settings_callback( $modulenow, $settings, $activate );

	// Captcha.
	secupress_captcha_settings_callback( $modulenow, $activate );

	// Login protection.
	secupress_login_protection_settings_callback( $modulenow, $settings, $activate );

	// Password Policy.
	secupress_password_policy_settings_callback( $modulenow, $settings, $activate );

	// Logins blacklist.
	secupress_logins_blacklist_settings_callback( $modulenow, $activate );

	// Move Login.
	secupress_move_login_settings_callback( $modulenow, $settings, $activate );

	return $settings;
}


/**
 * Double authentication plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_double_auth_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( ! empty( $activate['double-auth_type'] ) ) {
		secupress_manage_submodule( $modulenow, 'passwordless', '1' === $activate['double-auth_type'] && secupress_is_pro() );
	} elseif ( false !== $activate ) {
		secupress_deactivate_submodule( $modulenow, array( 'passwordless' ) );
	}

	// Affected roles.
	secupress_manage_affected_roles( $settings, $modulenow, 'double-auth' );
}


/**
 * Captcha plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_captcha_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'login-captcha', ! empty( $activate['captcha_activate'] ) );
	}
}


/**
 * Login protection plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_login_protection_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( ! empty( $activate['login-protection_type'] ) ) {
		$activate['login-protection_type'] = array_flip( $activate['login-protection_type'] );

		secupress_manage_submodule( $modulenow, 'limitloginattempts', isset( $activate['login-protection_type']['limitloginattempts'] ) );
		secupress_manage_submodule( $modulenow, 'bannonexistsuser',   isset( $activate['login-protection_type']['bannonexistsuser'] ) );
		secupress_manage_submodule( $modulenow, 'nonlogintimeslot',   isset( $activate['login-protection_type']['nonlogintimeslot'] ) );
	} elseif ( false !== $activate ) {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	// Settings.
	$settings['login-protection_number_attempts']  = ! empty( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']         = ! empty( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'],        1, 60, 5 )  : 5;
	$settings['login-protection_nonlogintimeslot'] = ! empty( $settings['login-protection_nonlogintimeslot'] ) && is_array( $settings['login-protection_nonlogintimeslot'] ) ? $settings['login-protection_nonlogintimeslot'] : array();

	$settings['login-protection_nonlogintimeslot']['from_hour']   = ! empty( $settings['login-protection_nonlogintimeslot']['from_hour'] )   ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['from_hour'],   0, 23, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['from_minute'] = ! empty( $settings['login-protection_nonlogintimeslot']['from_minute'] ) ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['from_minute'], 0, 59, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['to_hour']     = ! empty( $settings['login-protection_nonlogintimeslot']['to_hour'] )     ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['to_hour'],     0, 23, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['to_minute']   = ! empty( $settings['login-protection_nonlogintimeslot']['to_minute'] )   ? secupress_validate_range( (int) $settings['login-protection_nonlogintimeslot']['to_minute'],   0, 59, 0 ) : 0;

	// (De)Activation.
	if ( false !== $activate ) {
		$available = secupress_wp_version_is( '4.0' ) && secupress_is_pro();
		secupress_manage_submodule( $modulenow, 'only-one-connection', ! empty( $activate['login-protection_only-one-connection'] ) && $available );
		secupress_manage_submodule( $modulenow, 'sessions-control', ! empty( $activate['login-protection_sessions_control'] ) && $available );
	}
}


/**
 * Password policy plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_password_policy_settings_callback( $modulenow, &$settings, $activate ) {
	// Settings + (De)Activation.
	if ( secupress_is_pro() ) {
		$settings['password-policy_password_expiration'] = ! empty( $settings['password-policy_password_expiration'] ) ? absint( $settings['password-policy_password_expiration'] ) : 0;
		secupress_manage_submodule( $modulenow, 'password-expiration', $settings['password-policy_password_expiration'] > 0 ); // `$settings`, not `$activate`.
	} else {
		unset( $settings['password-policy_password_expiration'] );
		secupress_deactivate_submodule( $modulenow, array( 'password-expiration' ) );
	}

	// Affected roles.
	secupress_manage_affected_roles( $settings, $modulenow, 'password-policy' );

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'ask-old-password', ! empty( $activate['password-policy_ask-old-password'] ) );
		secupress_manage_submodule( $modulenow, 'strong-passwords', ! empty( $activate['password-policy_strong_passwords'] ) && secupress_is_pro() );
	}
}


/**
 * (De)Activate logins blacklist plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_logins_blacklist_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'blacklist-logins', ! empty( $activate['blacklist-logins_activated'] ) );
	}
}


/**
 * (De)Activate Move Login plugin. Sanitize and validate settings.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_move_login_settings_callback( $modulenow, &$settings, $activate ) {
	$old_settings = get_site_option( "secupress_{$modulenow}_settings" );
	// Slugs.
	$slugs        = secupress_move_login_slug_labels();
	// Handle forbidden slugs and duplicates.
	$errors       = array( 'forbidden' => array(), 'duplicates' => array() );
	// `postpass`, `retrievepassword` and `rp` are forbidden if they are not customizable.
	$forbidden    = array( 'postpass' => 1, 'retrievepassword' => 1, 'rp' => 1 );
	$forbidden    = array_diff_key( $forbidden, $slugs );
	$dones        = array();

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
		$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
		$message .= sprintf( _n( 'The slug %s is forbidden.', 'The slugs %s are forbidden.', $nbr_forbidden, 'secupress' ), wp_sprintf( '<code>%l</code>', $errors['forbidden'] ) );
		add_settings_error( "secupress_{$modulenow}_settings", 'forbidden-slugs', $message, 'error' );
	}

	if ( ! empty( $errors['duplicates'] ) ) {
		$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
		$message .= __( 'The links can\'t have the same slugs.', 'secupress' );
		add_settings_error( "secupress_{$modulenow}_settings", 'duplicate-slugs', $message, 'error' );
	}

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'move-login', ! empty( $activate['move-login_activated'] ) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* NOTICES ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_filter( 'secupress.plugins.packed-plugins', 'secupress_move_login_add_packed_plugin' );
/**
 * Display a notice if the standalone version of Move Login is used.
 *
 * @since 1.0
 *
 * @param (array) $plugins A list of plugin paths, relative to the plugins folder.
 */
function secupress_move_login_add_packed_plugin( $plugins ) {
	$plugins['move-login'] = 'sf-move-login/sf-move-login.php';
	return $plugins;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'secupress.first_install', 'secupress_install_users_login_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_install_users_login_module( $module ) {
	// First install.
	if ( 'all' === $module ) {
		// Activate "Ask for old password" submodule.
		secupress_activate_submodule_silently( 'users-login', 'ask-old-password' );
	}

	// First install or reset.
	if ( 'all' === $module || 'users-login' === $module ) {
		// Set default non-login time slot.
		update_site_option( 'secupress_users-login_settings', array(
			'login-protection_nonlogintimeslot' => array(
				'from_hour'   => 19,
				'from_minute' => 0,
				'to_hour'     => 8,
				'to_minute'   => 0,
			),
		) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DEFAULT VALUES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
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
	 * @param (array) $new_slugs An array with the action names as keys and field labels as values. An empty array by default.
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

/**
 * Move Login: return the list of available actions to perform when someone reaches the old login page.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_move_login_login_access_labels() {
	return array(
		'error'      => __( 'Display an error message', 'secupress' ),
		'redir_404'  => __( 'Redirect to a "Page Not Found" error page', 'secupress' ),
		'redir_home' => __( 'Redirect to the home page', 'secupress' ),
	);
}


/**
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
		'redir_404'   => __( 'Redirect to a "Page Not Found" error page', 'secupress' ),
		'redir_home'  => __( 'Redirect to the home page', 'secupress' ),
	);
}
