<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

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

	// Move Login.
	secupress_move_login_settings_callback( $modulenow, $settings, $activate );

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

	// Stop User Enumeration.
	secupress_stopuserenumeration_settings_callback( $modulenow, $activate );

	// Prevent User Creation
	secupress_preventusercreation_settings_callback( $modulenow, $activate );

	// Lock Default Role
	secupress_lock_default_role_settings_callback( $modulenow, $settings, $activate );

	// Lock Membership
	secupress_lock_membership_settings_callback( $modulenow, $activate );

	// Lock Admin Email
	secupress_lock_admin_email_settings_callback( $modulenow, $activate );


	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

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

	if ( ! empty( $activate['double-auth_type'] ) && ! secupress_is_submodule_active( 'users-login', 'passwordless' ) ) {
		secupress_manage_submodule( $modulenow, 'passwordless', '1' === $activate['double-auth_type'] && secupress_is_pro() );
	} elseif ( ! isset( $activate['double-auth_type'] ) && secupress_is_submodule_active( 'users-login', 'passwordless' ) ) {
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
	}
	secupress_manage_submodule( $modulenow, 'limitloginattempts', isset( $activate['login-protection_type']['limitloginattempts'] ) );
	secupress_manage_submodule( $modulenow, 'bannonexistsuser',   isset( $activate['login-protection_type']['bannonexistsuser'] ) );
	secupress_manage_submodule( 'discloses', 'login-errors-disclose', ! empty( $activate['login-protection_login_errors'] ) );

	// Settings.
	$settings['login-protection_number_attempts']  = ! empty( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']         = ! empty( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'],        1, 60, 5 )  : 5;

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'only-one-connection', ! empty( $activate['login-protection_only-one-connection'] ) );
		secupress_manage_submodule( $modulenow, 'sessions-control', ! empty( $activate['login-protection_sessions_control'] ) );
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
 * (De)Activate stop user enumeration plugin.
 *
 * @since 1.3
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_stopuserenumeration_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'stop-user-enumeration', ! empty( $activate['blacklist-logins_stop-user-enumeration'] ) );
	}
}

/**
 * (De)Activate prevent user creation plugin.
 *
 * @since 1.4.5.9
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_preventusercreation_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate && secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'prevent-user-creation', ! empty( $activate['blacklist-logins_prevent-user-creation'] ) );
	}
}


/**
 * (De)Activate lock default role plugin.
 *
 * @since 2.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_lock_default_role_settings_callback( $modulenow, $settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		if ( isset( $settings['blacklist-logins_default-role'] ) ) {
			$roles = new WP_Roles();
			$roles = $roles->get_names();
			$valid_role = ! empty( $activate['blacklist-logins_default-role-activated'] ) && in_array( $settings['blacklist-logins_default-role'], array_keys( $roles ) ) && ! isset( secupress_get_forbidden_default_roles()[ $settings['blacklist-logins_default-role'] ] );
			secupress_manage_submodule( $modulenow, 'default-role', $valid_role );
		} else {
			secupress_manage_submodule( $modulenow, 'default-role', false );
		}
	}

}


/**
 * (De)Activate lock membership plugin.
 *
 * @since 2.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_lock_membership_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'membership', ! empty( $activate['blacklist-logins_membership-activated'] ) );
	}

}


/**
 * (De)Activate lock admin email plugin.
 *
 * @since 2.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_lock_admin_email_settings_callback( $modulenow, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'admin-email', ! empty( $activate['blacklist-logins_admin-email-activated'] ) );
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
			/**
			 * Sanitization did its job til the end, or the field was empty.
			 * For the "login" slug don't fallback to the default slug: we'll keep it empty and trigger an error.
			 */
			if ( 'login' !== $default_slug ) {
				$new_slug = $fallback_slug;
			}
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
	if ( isset( $settings['move-login_login-access'] ) ) {
		$settings['move-login_login-access'] = sanitize_text_field( $settings['move-login_login-access'] );
	}

	// Handle validation errors.
	$errors['forbidden']  = array_unique( $errors['forbidden'] );
	$errors['duplicates'] = array_unique( $errors['duplicates'] );

	if ( false !== $activate && ! empty( $activate['move-login_activated'] ) ) {
		if ( empty( $settings['move-login_slug-login'] ) ) {
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
			$message .= __( 'Please choose your login URL.', 'secupress' );
			secupress_add_settings_error( "secupress_{$modulenow}_settings", 'forbidden-slugs', $message, 'error' );
		}

		if ( $nbr_forbidden = count( $errors['forbidden'] ) ) {
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
			$message .= sprintf( _n( 'The slug %s is forbidden.', 'The slugs %s are forbidden.', $nbr_forbidden, 'secupress' ), wp_sprintf( '<code>%l</code>', $errors['forbidden'] ) );
			secupress_add_settings_error( "secupress_{$modulenow}_settings", 'forbidden-slugs', $message, 'error' );
		}

		if ( ! empty( $errors['duplicates'] ) ) {
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
			$message .= __( 'The links can’t have the same slugs.', 'secupress' );
			secupress_add_settings_error( "secupress_{$modulenow}_settings", 'duplicate-slugs', $message, 'error' );
		}
	}

	// (De)Activation.
	if ( false !== $activate ) {
		if ( empty( $settings['move-login_slug-login'] ) ) {
			secupress_deactivate_submodule( $modulenow, array( 'move-login' ) );
		} else {
			secupress_manage_submodule( $modulenow, 'move-login', ! empty( $activate['move-login_activated'] ) );
		}
	}
	if ( isset( $activate['move-login_activated'] ) ) {
		$settings['move-login_whattodo'] = isset( $settings['move-login_whattodo'] ) ? $settings['move-login_whattodo'] : 'sperror';
	} else {
		unset( $settings['move-login_whattodo'] );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** INSTALL/RESET =============================================================================== */
/** --------------------------------------------------------------------------------------------- */
/*
add_action( 'secupress.first_install', 'secupress_install_****_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".

function secupress_install_users_login_module( $module ) {
	// First install.
	if ( 'all' === $module ) {
		// Activate "Ask for old password" submodule.
		secupress_activate_submodule_silently( '****', '****' );
	}

}
*/

/** --------------------------------------------------------------------------------------------- */
/** DEFAULT VALUES ============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Move Login: return the list of customizable login actions.
 *
 * @since 1.0
 * @since 1.3.1 Remove all other slugs than "login"
 * @since 1.3.2 Remove SFML hook, not compatible anymore
 *
 * @return (array) Return an array with the action names as keys and field labels as values.
 */
function secupress_move_login_slug_labels() {
	$labels = [ 'login' => __( 'New login page', 'secupress' ) ];
	if ( '1' === get_option( 'users_can_register' ) ) {
		$labels['register'] = __( 'New registration page', 'secupress' );
	}

	return $labels;
}
