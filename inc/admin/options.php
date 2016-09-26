<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* MAIN OPTION ================================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_init', 'secupress_register_global_setting' );
/**
 * Whitelist our global settings.
 *
 * @since 1.0
 */
function secupress_register_global_setting() {
	secupress_register_setting( 'global', SECUPRESS_SETTINGS_SLUG );
}


/**
 * Sanitize our global settings.
 *
 * @since 1.0
 *
 * @param (array) $value Our global settings.
 */
function secupress_global_settings_callback( $value ) {
	$value = $value ? $value : array();

	if ( isset( $value['sanitized'] ) ) {
		return $value;
	}
	$value['sanitized'] = 1;

	if ( ! secupress_is_pro() || ! empty( $value['wl_plugin_name'] ) && 'SecuPress' === $value['wl_plugin_name'] ) {
		unset( $value['wl_plugin_name'] );
	}

	/**
	 * License validation.
	 */
	$value['consumer_email'] = ! empty( $value['consumer_email'] ) ? sanitize_email( $value['consumer_email'] )    : '';
	$value['consumer_key']   = ! empty( $value['consumer_key'] )   ? sanitize_text_field( $value['consumer_key'] ) : '';

	if ( ! secupress_has_pro() ) {

		// Wut?!
		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );

	} elseif ( empty( $value['consumer_email'] ) ) {

		add_settings_error( 'secupress_global', 'response_error', __( 'Please provide a valid email address.', 'secupress' ) );
		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );

	} elseif ( empty( $value['consumer_key'] ) ) {

		add_settings_error( 'secupress_global', 'response_error', __( 'Please provide your license key.', 'secupress' ) );
		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );

	} else {
		// Default values related to the API.
		$def_values = array(
			'consumer_email' => '',
			'consumer_key'   => '',
			'wl_plugin_name' => '',
			'site_is_pro'    => 0,
		);

		// Previous values.
		$old_values = get_site_option( SECUPRESS_SETTINGS_SLUG );
		$old_values = is_array( $old_values ) ? $old_values : array();

		if ( empty( $old_values['wl_plugin_name'] ) || 'SecuPress' === $old_values['wl_plugin_name'] ) {
			unset( $old_values['wl_plugin_name'] );
		}

		$value = secupress_global_settings_update_api_subscription( $value, $old_values, $def_values );

		if ( empty( $value['site_is_pro'] ) ) {
			add_settings_error( 'secupress_global', 'response_error', __( 'Your license key seems invalid.', 'secupress' ) );
		}
	}

	return $value;
}


/**
 * Call our server to update the API subscription.
 *
 * @since 1.0
 *
 * @param (array) $new_values The new settings.
 * @param (array) $old_values The old settings.
 * @param (array) $def_values Default values related to the API.
 *
 * @return (array) $new_values The new settings, some values may have changed.
 */
function secupress_global_settings_update_api_subscription( $new_values, $old_values, $def_values ) {

	$api_old_values = secupress_array_merge_intersect( $old_values, $def_values );

	// Update the site in the user account.
	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'   => 'update_subscription',
		'user_email'  => $new_values['consumer_email'],
		'user_key'    => $new_values['consumer_key'],
		'plugin_name' => ! empty( $new_values['wl_plugin_name'] ) ? $new_values['wl_plugin_name'] : '',
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( $body = secupress_global_settings_api_request_succeeded( $response, $new_values ) ) {
		// Success!
		$new_values['consumer_key'] = sanitize_text_field( $body->data->user_key );
		$new_values['site_is_pro']  = (int) ! empty( $body->data->site_is_pro );
	} else {
		// Keep old values.
		$new_values['consumer_email'] = $api_old_values['consumer_email'];
		$new_values['consumer_key']   = $api_old_values['consumer_key'];
	}

	return $new_values;
}


/**
 * Trigger a settings error if the given API request failed.
 *
 * @since 1.0
 *
 * @param (mixed) $response   The request response.
 * @param (array) $new_values The new settings, passed by reference. Depending on the request result, these values may be changed.
 *
 * @return (mixed) The response body. False otherwise.
 */
function secupress_global_settings_api_request_succeeded( $response, &$new_values ) {

	if ( is_wp_error( $response ) ) {
		// The request couldn't be sent.
		add_settings_error( 'secupress_global', 'request_error', __( 'Something on your website is preventing the request to be sent.', 'secupress' ) );
		return false;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		// The server couldn't be reached. Maybe a server error or something.
		add_settings_error( 'secupress_global', 'server_error', __( 'Our server is not accessible at the moment, please try again later.', 'secupress' ) );
		return false;
	}

	$body = wp_remote_retrieve_body( $response );
	$body = @json_decode( $body );

	if ( ! is_object( $body ) ) {
		// The response is not a json.
		add_settings_error( 'secupress_global', 'server_bad_response', __( 'Our server returned an unexpected response and might be in error, please try again later or contact our support team.', 'secupress' ) );
		return false;
	}

	if ( empty( $body->success ) ) {
		// The response is an error.
		if ( 'invalid_api_credential' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'There is a problem with your license key, please contact our support team.', 'secupress' ) );
			unset( $new_values['consumer_key'], $new_values['site_is_pro'] );

		} elseif ( 'invalid_email' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'The email address is invalid.', 'secupress' ) );

		} else {
			add_settings_error( 'secupress_global', 'response_error', __( 'Our server returned an error, please try again later or contact our support team.', 'secupress' ) );
		}

		return false;
	}

	return $body;
}


/*------------------------------------------------------------------------------------------------*/
/* MODULES OPTIONS ============================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_init', 'secupress_register_all_settings' );
/**
 * Register all modules settings.
 *
 * @since 1.0
 */
function secupress_register_all_settings() {
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module_data ) {
			secupress_register_setting( $key );
		}
	}
}
