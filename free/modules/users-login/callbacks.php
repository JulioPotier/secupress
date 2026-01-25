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
	if ( function_exists( 'secupress_pro_double_auth_settings_callback' ) ) {
		secupress_pro_double_auth_settings_callback( $modulenow, $settings, $activate );
	}

	// Captcha.
	secupress_captcha_settings_callback( $modulenow, $settings, $activate );

	// Login protection.
	secupress_login_protection_settings_callback( $modulenow, $settings, $activate );

	// Password Policy.
	secupress_password_policy_settings_callback( $modulenow, $settings, $activate );

	// Logins blacklist.
	secupress_logins_blacklist_settings_callback( $modulenow, $settings, $activate );

	// Stop User Enumeration.
	secupress_stopuserenumeration_settings_callback( $modulenow, $activate );

	// Prevent User Creation
	secupress_preventusercreation_settings_callback( $modulenow, $settings, $activate );

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
 * Captcha plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_captcha_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'login-captcha', ! empty( $activate['captcha_activate'] ) );
		if ( 'challenge' === $settings['captcha_captcha-style'] ) {
			$sets = secupress_get_emojiset( 'all' );
			$settings['captcha_emoji-set'] = 'random' || isset( $sets[ $settings['captcha_emoji-set'] ] ) ? $settings['captcha_emoji-set'] : reset( $sets );
		}
	} else {
		unset( $settings['captcha_emoji-set'] );
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
	secupress_manage_submodule( $modulenow, 'geoip-login', isset( $activate['login-protection_geoip_login'] ) );
	secupress_manage_affected_roles( $settings, $modulenow, 'login-protection_geoip_login' );
	secupress_manage_submodule( $modulenow, 'limitloginattempts', isset( $activate['login-protection_type']['limitloginattempts'] ) );
	secupress_manage_submodule( $modulenow, 'passwordspraying', isset( $activate['login-protection_type']['passwordspraying'] ) );
	secupress_manage_submodule( $modulenow, 'bannonexistsuser',   isset( $activate['login-protection_type']['bannonexistsuser'] ) );
	secupress_manage_submodule( 'discloses', 'login-errors-disclose', ! empty( $activate['login-protection_login_errors'] ) );

	// Settings.
	$settings['login-protection_number_attempts']  = ! empty( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']         = ! empty( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'],        1, 60, 5 )  : 5;

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'only-one-connection', ! empty( $activate['login-protection_only-one-connection'] ) ); // Old module
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
	global $wpdb;
	// Settings + (De)Activation.
	if ( secupress_is_pro() ) {
		$settings['password-policy_password_expiration'] = ! empty( $settings['password-policy_password_expiration'] ) ? absint( $settings['password-policy_password_expiration'] ) : '0';
		if ( $settings['password-policy_password_expiration'] !== secupress_get_module_option( 'password-policy_password_expiration', '0', 'users-login' ) ) {
			// 2.3.19 we do not activate this module here, "strong password" will include it if needed
			// secupress_manage_submodule( $modulenow, 'password-expiration', $settings['password-policy_password_expiration'] > 0 ); // `$settings`, not `$activate`.
			secupress_add_module_notice( '', __( 'Password Lifespan', 'secupress' ), $settings['password-policy_password_expiration'] > 0 ? 'activation' : 'deactivation' );
		} else {
			unset( $settings['password-policy_password_expiration'] );
		}
	}

	// Do not use secupress_manage_submodule() to prevent to trigger the activation hook every time
	if ( ! secupress_is_submodule_active( 'users-login', 'force-strong-encryption' ) && ! empty( $activate['double-auth_force-strong-encryption'] ) ) {
		secupress_activate_submodule( $modulenow, 'force-strong-encryption' );
	}
	if ( secupress_is_submodule_active( 'users-login', 'force-strong-encryption' ) && empty( $activate['double-auth_force-strong-encryption'] ) ) {
		secupress_deactivate_submodule( $modulenow, 'force-strong-encryption' );
	}
	if ( secupress_is_pro() && secupress_is_submodule_active( 'users-login', 'force-strong-encryption' ) ) {
		
		$settings['double-auth_prevent-low-encryption'] = (int) isset( $settings['double-auth_prevent-low-encryption'] );
		if ( $settings['double-auth_prevent-low-encryption'] !== secupress_get_module_option( 'double-auth_prevent-low-encryption', 0, 'users-login' ) ) {
			secupress_add_module_notice( '', __( 'Prevent other encryption system to log in', 'secupress' ), (int) $settings['double-auth_prevent-low-encryption'] > 0 ? 'activation' : 'deactivation' );
			_secupress_force_strong_encryption_set_rehash_meta();
		} elseif ( ! isset( $settings['double-auth_prevent-low-encryption'] ) ) {
			delete_metadata( 'user', false, 'secupress-password-needs-rehash', '', true );
		}		

		$settings['double-auth_prevent-hash-reuse'] = (int) isset( $settings['double-auth_prevent-hash-reuse'] );
		if ( $settings['double-auth_prevent-hash-reuse'] !== secupress_get_module_option( 'double-auth_prevent-hash-reuse', 0, 'users-login' ) ) {
			secupress_add_module_notice( '', __( 'Prevent Reuse of Password Hashes', 'secupress' ), (int) $settings['double-auth_prevent-hash-reuse'] > 0 ? 'activation' : 'deactivation' );
			if ( (int) $settings['double-auth_prevent-hash-reuse'] ) {
				$index_exists = $wpdb->get_row(
					"SHOW INDEX FROM $wpdb->users WHERE Key_name = 'unique_user_pass'"
				);

				if ( ! $index_exists ) {
					$wpdb->query( "ALTER TABLE $wpdb->users ADD UNIQUE INDEX unique_user_pass (user_pass)" );
				}
			} else {
				$wpdb->query( "ALTER TABLE $wpdb->users DROP INDEX unique_user_pass" );
			}
		}
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
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_logins_blacklist_settings_callback( $modulenow, $settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		$settings['blacklist-logins_admin']  = (int) ! empty( $settings['blacklist-logins_admin'] );
		$settings['blacklist-logins_lexicomatisation']  = (int) ! empty( $settings['blacklist-logins_lexicomatisation'] );
		secupress_manage_submodule( $modulenow, 'blacklist-logins', ! empty( $activate['blacklist-logins_activated'] ) );
	}
	return $settings;
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
 * @since 2.2.6
 *
 * @param (string)     $modulenow Current module.
 * @param (array|bool) $activate  An array containing the fields related to the sub-module being activated. False if not on this module page.
 */
function secupress_preventusercreation_settings_callback( $modulenow, &$settings, $activate ) {
	if ( false === $activate ) {
		return;
	}
	$db_opt             = secupress_get_module_option( 'user_protection_confirm', false, $modulenow );
	$confirmed          = $db_opt || isset( $settings['blacklist-logins_confirm'] );
	$user_prot_activate = isset( $activate['blacklist-logins_user-creation-protection'] ) && $activate['blacklist-logins_user-creation-protection'];

	// (De)Activation.
	$settings['blacklist-logins_admin'] = isset( $settings['blacklist-logins_admin'] ) ? '1' : '0';
	if ( $settings['blacklist-logins_admin'] !== secupress_get_module_option( 'blacklist-logins_admin', '0', 'users-login' ) ) {
		secupress_add_module_notice( '', sprintf( __( 'Forbid «%s» Usernames', 'secupress' ), 'admin' ), $settings['blacklist-logins_admin'] ? 'activation' : 'deactivation' );
		if ( secupress_is_pro() ) {
			secupress_set_submodule_alert( 'users-login', sprintf( __( 'Forbid «%s» Usernames', 'secupress' ), 'admin' ) );
		}		
	}
	$settings['blacklist-logins_lexicomatisation'] = isset( $settings['blacklist-logins_lexicomatisation'] ) ? '1' : '0';
	if ( $settings['blacklist-logins_lexicomatisation'] !== secupress_get_module_option( 'blacklist-logins_lexicomatisation', '0', 'users-login' ) ) {
		secupress_add_module_notice( '', __( 'Rename public user names', 'secupress' ), $settings['blacklist-logins_lexicomatisation'] ? 'activation' : 'deactivation' );
	}
	////secupress_manage_submodule( $modulenow, 'prevent-reset-password', isset( $activate['blacklist-logins_prevent-reset-password'] ) );
	secupress_manage_submodule( $modulenow, 'same-email-domain', isset( $activate['blacklist-logins_same-email-domain'] ) );
	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'user-creation-protection', $confirmed && $user_prot_activate );
		secupress_manage_submodule( $modulenow, 'prevent-user-creation',    $user_prot_activate && isset( $activate['blacklist-logins_prevent-user-creation'] ) );
		secupress_manage_submodule( $modulenow, 'bad-email-domains',        isset( $activate['blacklist-logins_bad-email-domains'] ) );
	}

	if ( ! secupress_is_submodule_active( $modulenow, 'user-creation-protection' ) ) {
		secupress_deactivate_submodule( $modulenow, 'prevent-user-creation' );
		unset( $settings['user_protection_confirm'] );
	} else {
		$settings['user_protection_confirm'] = 1;
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
			secupress_manage_submodule( $modulenow, 'default-role', isset( $activate['blacklist-logins_default-role-activated'] ) );
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
			$message .= __( 'Please select your login page.', 'secupress' );
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
			secupress_manage_submodule( $modulenow, 'move-login',   ! empty( $activate['move-login_activated'] ) );
			secupress_manage_submodule( $modulenow, 'singlesignon', ! empty( $activate['move-login_singlesignon'] ) );
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