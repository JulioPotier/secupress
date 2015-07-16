<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_users_login_settings' );
function secupress_register_users_login_settings() {
	register_setting( "secupress_users_login_settings", "secupress_users_login_settings", "__secupress_users_login_settings_callback" );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_users_login_settings_callback( $settings ) {
	$modulenow = 'users_login';

	/* double_auth */
	switch ( $settings['plugin_double_auth'] ) {

		case 'password':
			$actual_double_auth_password = get_secupress_module_option( 'double_auth_password', false, $modulenow );
			if ( strlen( $settings['double_auth_password'] ) < 7 || $settings['password_strength_value'] < 3 ) {
				if ( ! $actual_double_auth_password ) {
					$settings['plugin_double_auth'] = '-1';
					$settings['double_auth_password'] = '';
					secupress_deactivate_submodule( $modulenow, 'password' );
				} else {
					$settings['double_auth_password'] = $actual_double_auth_password;
				}
			} else {
				secupress_activate_submodule( $modulenow, 'password', array( 'notif', 'emaillink', 'googleauth' ) );
				if ( strlen( $settings['double_auth_password'] ) > 0 ) {
					$settings['double_auth_password'] = wp_hash_password( $settings['double_auth_password'] );
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

	if ( 'password' != $settings['plugin_double_auth'] ) {
		$settings['double_auth_password'] = '';
	}

	secupress_manage_affected_roles( $settings, 'double_auth' );

	unset( $settings['password_strength_value'] ); // not actual option

	if ( isset( $settings['profile_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'profile_protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile_protect' );
	}
	secupress_manage_affected_roles( $settings, 'profile_protect' );

	/* bad_logins */
	if ( isset( $settings['plugin_bad_logins'] ) ) {
		if ( in_array( 'bannonexistsuser', $settings['plugin_bad_logins'] ) ) {
			secupress_activate_submodule( $modulenow, 'bannonexistsuser' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'bannonexistsuser' );
		}
		if ( in_array( 'limitloginattempts', $settings['plugin_bad_logins'] ) ) {
			secupress_activate_submodule( $modulenow, 'limitloginattempts' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'limitloginattempts' );
		}
		if ( in_array( 'nonlogintimeslot', $settings['plugin_bad_logins'] ) ) {
			secupress_activate_submodule( $modulenow, 'nonlogintimeslot' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'nonlogintimeslot' );
		}	
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'ooc', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	$settings['bad_logins_number_attempts'] = isset( $settings['bad_logins_number_attempts'] ) && secupress_validate_range( $settings['bad_logins_number_attempts'], 3, 99 ) ? $settings['bad_logins_number_attempts'] : 10;
	$settings['bad_logins_time_ban'] = isset( $settings['bad_logins_time_ban'] ) && secupress_validate_range( $settings['bad_logins_time_ban'], 1, 60 ) ? $settings['bad_logins_time_ban'] : 5;
	if ( ! isset( $settings['bad_logins_nonlogintimeslot'] ) ) {
		$settings['bad_logins_nonlogintimeslot'] = array();
	}
	$settings['bad_logins_nonlogintimeslot']['from_hour'] = isset( $settings['bad_logins_nonlogintimeslot']['from_hour'] ) && secupress_validate_range( $settings['bad_logins_nonlogintimeslot']['from_hour'], 0, 23 ) ? (int) $settings['bad_logins_nonlogintimeslot']['from_hour'] : 0;
	$settings['bad_logins_nonlogintimeslot']['from_minute'] = isset( $settings['bad_logins_nonlogintimeslot']['from_minute'] ) && in_array( $settings['bad_logins_nonlogintimeslot']['from_minute'], array( '0', '15', '30', '45' ) ) ? (int) $settings['bad_logins_nonlogintimeslot']['from_minute'] : 0;
	$settings['bad_logins_nonlogintimeslot']['to_hour'] = isset( $settings['bad_logins_nonlogintimeslot']['to_hour'] ) && secupress_validate_range( $settings['bad_logins_nonlogintimeslot']['to_hour'], 0, 23 ) ? (int) $settings['bad_logins_nonlogintimeslot']['to_hour'] : 0;
	$settings['bad_logins_nonlogintimeslot']['to_minute'] = isset( $settings['bad_logins_nonlogintimeslot']['to_minute'] ) && in_array( $settings['bad_logins_nonlogintimeslot']['to_minute'], array( '0', '15', '30', '45' ) ) ? (int) $settings['bad_logins_nonlogintimeslot']['to_minute'] : 0;
	
	if ( isset( $settings['plugin_captcha'] ) ) {
			secupress_activate_submodule( $modulenow, 'login_captcha' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'login_captcha' );
	}

	return $settings;
}

function secupress_fix_easy_login() {
	$settings = array( 'plugin_double_auth' => 'emaillink', 'double_auth_affected_role' => array() );
	secupress_activate_module( 'users_login', $settings );
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success();
	} else {
		wp_safe_redirect( wp_get_referer() );
		die();
	}
}