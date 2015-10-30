<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_users_login_settings_callback( $settings ) {
	$modulenow = 'users-login';
	$settings = $settings ? $settings : array();

	// double-auth
	if ( isset( $settings['double-auth_type'] ) ) {
		switch ( $settings['double-auth_type'] ) {

			case 'password':
				$actual_double_auth_password = secupress_get_module_option( 'double-auth_password', false, $modulenow );
				if ( strlen( $settings['double-auth_password'] ) < 7 || $settings['temp.password_strength_value'] < 3 ) {
					if ( ! $actual_double_auth_password ) {
						$settings['double-auth_type'] = '-1';
						$settings['double-auth_password'] = '';
						secupress_deactivate_submodule( $modulenow, 'password' );
					} else {
						$settings['double-auth_password'] = $actual_double_auth_password;
					}
				} else {
					secupress_activate_submodule( $modulenow, 'password', array( 'notif', 'emaillink', 'googleauth' ) );
					if ( strlen( $settings['double-auth_password'] ) > 0 ) {
						$settings['double-auth_password'] = wp_hash_password( $settings['double-auth_password'] );
					}
				}
			break;

			case 'googleauth':
				secupress_activate_submodule( $modulenow, 'googleauth', array( 'password', 'notif', 'emaillink' ) );
			break;

			case 'emaillink':
				secupress_activate_submodule( $modulenow, 'emaillink', array( 'password', 'notif', 'googleauth' ) );
			break;

			default:
				secupress_deactivate_submodule( $modulenow, array( 'password', 'notif', 'emaillink', 'googleauth' ) );
			break;
		}

		if ( 'password' != $settings['double-auth_type'] ) {
			$settings['double-auth_password'] = '';
		}
	}

	secupress_manage_affected_roles( $settings, 'double-auth' );

	unset( $settings['temp.password_strength_value'] ); // not actual option

	if ( isset( $settings['profile_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'profile-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile-protect' );
	}
	secupress_manage_affected_roles( $settings, 'profile-protect' );

	// login-protection
	if ( isset( $settings['login-protection_type'] ) ) {
		if ( in_array( 'bannonexistsuser', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'bannonexistsuser' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'bannonexistsuser' );
		}
		if ( in_array( 'limitloginattempts', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'limitloginattempts' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'limitloginattempts' );
		}
		if ( in_array( 'nonlogintimeslot', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'nonlogintimeslot' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'nonlogintimeslot' );
		}
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'ooc', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	$settings['login-protection_number_attempts'] = isset( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']        = isset( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'], 1, 60, 5 )         : 5;
	if ( ! isset( $settings['login-protection_nonlogintimeslot'] ) ) {
		$settings['login-protection_nonlogintimeslot'] = array();
	}
	$settings['login-protection_nonlogintimeslot']['from_hour']   = isset( $settings['login-protection_nonlogintimeslot']['from_hour'] )   ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['from_hour'], 0, 23, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['from_minute'] = isset( $settings['login-protection_nonlogintimeslot']['from_minute'] ) && in_array( $settings['login-protection_nonlogintimeslot']['from_minute'], array( '0', '15', '30', '45' ) ) ? (int) $settings['login-protection_nonlogintimeslot']['from_minute'] : 0;
	$settings['login-protection_nonlogintimeslot']['to_hour']     = isset( $settings['login-protection_nonlogintimeslot']['to_hour'] )     ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['to_hour'], 0, 23, 0 )   : 0;
	$settings['login-protection_nonlogintimeslot']['to_minute']   = isset( $settings['login-protection_nonlogintimeslot']['to_minute'] )   && in_array( $settings['login-protection_nonlogintimeslot']['to_minute'], array( '0', '15', '30', '45' ) )   ? (int) $settings['login-protection_nonlogintimeslot']['to_minute']   : 0;

	if ( isset( $settings['captcha_type'] ) ) {
		secupress_activate_submodule( $modulenow, 'login-captcha' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'login-captcha' );
	}

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

// Create default option on install.

add_action( 'wp_secupress_first_install', '__secupress_install_users_login_module' );

function __secupress_install_users_login_module( $module = 'all' ) {
	if ( 'all' === $module || 'users_login' === $module ) {
		update_option( 'secupress_users_login_settings', array(
			'double-auth_type' => '-1',
			//// pas fini
		) );
	}
}
