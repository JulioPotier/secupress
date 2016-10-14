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

	// Previous values.
	$old_values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_values = is_array( $old_values ) ? $old_values : array();
	unset( $old_values['sanitized'] );

	/**
	 * White Label.
	 */
	if ( ! secupress_is_pro() && ! empty( $value['wl_plugin_name'] ) ) {
		// Trick the referrer for the redirection.
		$old_slug = ! empty( $old_values['wl_plugin_name'] ) ? sanitize_title( $old_values['wl_plugin_name'] ) : 'secupress';
		$old_slug = 'page=' . $old_slug . '_settings';
		$new_slug = 'page=secupress_settings';

		$_REQUEST['_wp_http_referer'] = str_replace( $old_slug, $new_slug, wp_get_raw_referer() );
	}

	if ( ! secupress_is_pro() || empty( $value['wl_plugin_name'] ) || 'SecuPress' === $value['wl_plugin_name'] ) {
		unset( $value['wl_plugin_name'] );
	}

	/**
	 * License validation.
	 */
	$has_email = ! empty( $value['consumer_email'] );
	$has_key   = ! empty( $value['consumer_key'] );

	$value['consumer_email'] = $has_email ? sanitize_email( $value['consumer_email'] )    : '';
	$value['consumer_key']   = $has_key   ? sanitize_text_field( $value['consumer_key'] ) : '';

	// Default values related to the license.
	$def_values = array(
		'consumer_email' => '',
		'consumer_key'   => '',
		'site_is_pro'    => 0,
	);

	if ( empty( $old_values['wl_plugin_name'] ) || 'SecuPress' === $old_values['wl_plugin_name'] ) {
		unset( $old_values['wl_plugin_name'] );
	}

	if ( ! secupress_has_pro() || ! $has_email || ! $has_key ) {

		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );

	} elseif ( ! $value['consumer_email'] || ! $value['consumer_key'] ) {

		if ( ! $value['consumer_email'] ) {
			add_settings_error( 'secupress_global', 'response_error', __( 'Please provide a valid email address.', 'secupress' ) );
		}
		if ( ! $value['consumer_key'] ) {
			add_settings_error( 'secupress_global', 'response_error', __( 'Please provide your license key.', 'secupress' ) );
		}

		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );

	} else {

		$value = secupress_global_settings_activate_pro_license( $value, $old_values, $def_values );

		if ( empty( $value['site_is_pro'] ) && ! get_settings_errors( 'secupress_global' ) ) {
			add_settings_error( 'secupress_global', 'response_error', __( 'Your license key seems invalid.', 'secupress' ) );
		}
	}

	/**
	 * Deal with values that are not set via the settings page's form.
	 */
	$pro_values = array_merge( $def_values, array(
		'wl_plugin_name' => '',
		'wl_plugin_URI'  => '',
		'wl_description' => '',
		'wl_author'      => '',
		'wl_author_URI'  => '',
	) );
	$old_values = array_diff_key( $old_values, $pro_values );
	$value      = array_merge( $old_values, $value );

	return $value;
}


/**
 * Call our server to activate the Pro license.
 *
 * @since 1.0
 *
 * @param (array) $new_values The new settings.
 * @param (array) $old_values The old settings.
 * @param (array) $def_values Default values related to the license.
 *
 * @return (array) $new_values The new settings, some values may have changed.
 */
function secupress_global_settings_activate_pro_license( $new_values, $old_values, $def_values ) {

	$api_old_values = secupress_array_merge_intersect( $old_values, $def_values );

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'  => 'activate_pro_license',
		'user_email' => $new_values['consumer_email'],
		'user_key'   => $new_values['consumer_key'],
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( $body = secupress_global_settings_api_request_succeeded( $response, $new_values ) ) {
		// Success!
		$new_values['consumer_key'] = sanitize_text_field( $body->data->user_key );

		if ( ! empty( $body->data->site_is_pro ) ) {
			$new_values['site_is_pro'] = 1;
		} else {
			unset( $new_values['site_is_pro'] );
		}
	} else {
		// Keep old values.
		$new_values['consumer_email'] = $api_old_values['consumer_email'];
		$new_values['consumer_key']   = $api_old_values['consumer_key'];

		if ( $api_old_values['site_is_pro'] ) {
			// Don't invalid the license because we couldn't reach our server or things like that.
			$new_values['site_is_pro'] = 1;
		} else {
			unset( $new_values['site_is_pro'] );
		}
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
 * @return (object|bool) The response body on success. False otherwise.
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
		if ( ! empty( $body->data->code ) && 'invalid_api_credential' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'There is a problem with your license key, please contact our support team.', 'secupress' ) );
			unset( $new_values['consumer_key'], $new_values['site_is_pro'] );

		} elseif ( ! empty( $body->data->code ) && 'invalid_email' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'The email address is invalid.', 'secupress' ) );

		} elseif ( ! empty( $body->data->code ) && 'invalid_customer' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'This email address is not in our database.', 'secupress' ) );
			unset( $new_values['consumer_key'], $new_values['site_is_pro'] );

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
