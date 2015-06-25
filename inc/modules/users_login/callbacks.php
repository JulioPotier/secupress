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
			$all_submodules = apply_filters( 'deactivate_all_submodules', array( 'password', 'notif', 'emaillink', 'googleauth' ) );
			secupress_deactivate_submodule( $modulenow, $all_submodules );
			break;
	}

	if ( 'password' != $settings['plugin_double_auth'] ) {
		$settings['double_auth_password'] = '';
	}

	if ( isset( $settings['hidden_double_auth_affected_role'] ) ) {
		$settings['double_auth_affected_role'] = array_diff( $settings['hidden_double_auth_affected_role'], $settings['double_auth_affected_role'] );
	}

	unset( $settings['password_strength_value'], $settings['hidden_double_auth_affected_role'] ); // not actual options
	return $settings;
}

function secupress_fix_easy_login() {
	$settings = array( 'plugin_double_auth' => 'emaillink', 'double_auth_affected_role' => array() );
	secupress_activate_module( 'users_login', $settings );
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success();
	} else {
		// war_dump( $GLOBALS['secupress_modules'] );
		wp_safe_redirect( wp_get_referer() );
		die();
	}
}