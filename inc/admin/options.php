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

	if ( ! empty( $old_values['wl_plugin_name'] ) && 'SecuPress' === $old_values['wl_plugin_name'] ) {
		unset( $old_values['wl_plugin_name'] );
	}

	if ( ! secupress_is_pro() || ! empty( $value['wl_plugin_name'] ) && 'SecuPress' === $value['wl_plugin_name'] ) {
		unset( $value['wl_plugin_name'] );
	}

	/**
	 * API and license validation.
	 */// ////.
	/*$value['consumer_email'] = ! empty( $value['consumer_email'] ) ? is_email( $value['consumer_email'] )          : '';
	$value['consumer_key']   = ! empty( $value['consumer_key'] )   ? sanitize_text_field( $value['consumer_key'] ) : '';

	// Default values related to the API.
	$def_values = array(
		'consumer_email' => '',
		'consumer_key'   => '',
		'wl_plugin_name' => '',
		'site_is_pro'    => 0,
	);

	$has_old_api_values = ! empty( $old_values['consumer_email'] ) && ! empty( $old_values['consumer_key'] );

	// Email removed: remove the site from the user account.
	if ( ! $value['consumer_email'] && $has_old_api_values ) {
		$value = secupress_global_settings_remove_api_subscription( $value, $old_values, $def_values );
	}
	// Email is (still) empty, move along.
	elseif ( ! $value['consumer_email'] ) {
		unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );
	}
	// We have a valid email address: add the site.
	else {
		$value = secupress_global_settings_update_api_subscription( $value, $old_values, $def_values );
	}

	// Uptime monitor.
	if ( ! empty( $old_values['uptime_monitoring_account_key'] ) && ! empty( $old_values['uptime_monitoring_site_key'] ) ) {
		$value['uptime_monitoring_account_key'] = $old_values['uptime_monitoring_account_key'];
		$value['uptime_monitoring_site_key']    = $old_values['uptime_monitoring_site_key'];
	} else {
		unset( $value['uptime_monitoring_account_key'], $value['uptime_monitoring_site_key'] );
	}*/

	return $value;
}


/**
 * Call our server to remove the API subscription.
 *
 * @since 1.0
 *
 * @param (array) $new_values The new settings.
 * @param (array) $old_values The old settings.
 * @param (array) $def_values Default values related to the API.
 *
 * @return (array) $new_values The new settings, some values may have changed.
 */// ////.
/*function secupress_global_settings_remove_api_subscription( $new_values, $old_values, $def_values ) {

	$api_old_values = secupress_array_merge_intersect( $old_values, $def_values );

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'  => 'remove_subscription',
		'user_email' => $api_old_values['consumer_email'],
		'user_key'   => $api_old_values['consumer_key'],
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( secupress_global_settings_api_request_succeeded( $response, $new_values ) ) {
		// Success!
		unset( $new_values['consumer_email'], $new_values['consumer_key'], $new_values['site_is_pro'] );

		$api_new_values = secupress_array_merge_intersect( $new_values, $def_values );
		/**
		 * Fires when the data related to the API change, after being sent to the server.
		 *
		 * @since 1.0
		 *
		 * @param (array) $api_new_values The new values.
		 * @param (array) $api_old_values The old values.
		 *//*
		do_action( 'secupress.api.data_changed', $api_new_values, $api_old_values );
	} else {
		// Keep old values.
		$new_values['consumer_email'] = $api_old_values['consumer_email'];
		$new_values['consumer_key']   = $api_old_values['consumer_key'];
	}

	return $new_values;
}
*/


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
 */// ////.
/*function secupress_global_settings_update_api_subscription( $new_values, $old_values, $def_values ) {

	$api_old_values = secupress_array_merge_intersect( $old_values, $def_values );

	// One does not simply remove the API key.
	if ( $api_old_values['consumer_email'] === $new_values['consumer_email'] && $api_old_values['consumer_key'] && ! $new_values['consumer_key'] ) {
		// If the email does not change, forbid to remove the key.
		$new_values['consumer_key'] = $api_old_values['consumer_key'];
	}

	// Update the site in the user account.
	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'   => 'update_subscription',
		'user_email'  => $new_values['consumer_email'],
		'user_key'    => $new_values['consumer_key'],
		'plugin_name' => ! empty( $new_values['wl_plugin_name'] ) ? $new_values['wl_plugin_name'] : '',
		// Allow to change the email address (and so, move the site from an account to a new one).
		'prev_email'  => $api_old_values['consumer_email'] && $api_old_values['consumer_email'] !== $new_values['consumer_email'] ? $api_old_values['consumer_email'] : '',
		'prev_key'    => $api_old_values['consumer_key'] ? $api_old_values['consumer_key'] : '',
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( $body = secupress_global_settings_api_request_succeeded( $response, $new_values ) ) {
		// Success!
		$new_values['consumer_key'] = sanitize_text_field( $body->data->user_key );
		$new_values['site_is_pro']  = (int) ! empty( $body->data->site_is_pro );

		// Test if something changed.
		$api_new_values = secupress_array_merge_intersect( $new_values, $def_values );

		if ( $api_old_values !== $api_new_values ) {
			/** This action is documented in inc/admin/options.php *//*
			do_action( 'secupress.api.data_changed', $api_new_values, $api_old_values );
		}
	} else {
		// Keep old values.
		$new_values['consumer_email'] = $api_old_values['consumer_email'];
		$new_values['consumer_key']   = $api_old_values['consumer_key'];
	}

	return $new_values;
}
*/


/**
 * Trigger a settings error if the given API request failed.
 *
 * @since 1.0
 *
 * @param (mixed) $response   The request response.
 * @param (array) $new_values The new settings, passed by reference. Depending on the request result, these values may be changed.
 *
 * @return (mixed) The response body. False otherwise.
 */// ////.
/*function secupress_global_settings_api_request_succeeded( $response, &$new_values ) {

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

			add_settings_error( 'secupress_global', 'response_error', __( 'There is a problem with your API key, please contact our support team to reset it.', 'secupress' ) );
			unset( $new_values['consumer_key'], $new_values['site_is_pro'] );

		} elseif ( 'invalid_email' === $body->data->code ) {

			add_settings_error( 'secupress_global', 'response_error', __( 'The email address is invalid.', 'secupress' ) );

		} else {
			add_settings_error( 'secupress_global', 'response_error', __( 'Our server returned an error, please try again later or contact our support team.', 'secupress' ) );
		}

		return false;
	}

	return $body;
}*/


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


/*------------------------------------------------------------------------------------------------*/
/* TRACK CHANGES IN CONSUMER EMAIL ============================================================== */
/*------------------------------------------------------------------------------------------------*/

/* //// add_action( 'add_site_option_' . SECUPRESS_SETTINGS_SLUG,    'secupress_updated_consumer_email_option', 20, 2 );
add_action( 'update_site_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_updated_consumer_email_option', 20, 3 );
/**
 * If the consumer email address is changed, trigger a custom event.
 *
 * @since 1.0
 *
 * @param (string) $option   Name of the option.
 * @param (mixed)  $newvalue The new value of the option.
 * @param (mixed)  $oldvalue The old value of the option.
 *//*
function secupress_updated_consumer_email_option( $option, $newvalue, $oldvalue = false ) {
	$old_email = isset( $oldvalue['consumer_email'] ) ? is_email( $oldvalue['consumer_email'] ) : false;
	$new_email = isset( $newvalue['consumer_email'] ) ? is_email( $newvalue['consumer_email'] ) : false;

	if ( ! $old_email && ! $new_email ) {
		return;
	}

	if ( ! $new_email ) {
		/**
		 * Fires after the consumer email has been deleted.
		 *
		 * @since 1.0
		 *
		 * @param (string) $old_email The old consumer email address.
		 *//*
		do_action( 'secupress.deleted-consumer_email', $old_email );
		return;
	}

	if ( ! $old_email ) {
		/**
		 * Fires after the consumer email has been added.
		 *
		 * @since 1.0
		 *
		 * @param (string) $new_email The new consumer email address.
		 *//*
		do_action( 'secupress.added-consumer_email', $new_email );
		return;
	}

	if ( $old_email !== $new_email ) {
		/**
		 * Fires after the consumer email has been updated.
		 *
		 * @since 1.0
		 *
		 * @param (string) $new_email The new consumer email address.
		 * @param (string) $old_email The old consumer email address.
		 *//*
		do_action( 'secupress.updated-consumer_email', $new_email, $old_email );
	}
}


add_action( 'pre_delete_site_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_before_delete_consumer_email_option', 20 );
/**
 * Before deleting the whole option, test if the consumer email exists.
 * Store the current value and use it later in `secupress_deleted_consumer_email_option()`.
 * This way we can trigger a custom event only if there was a value.
 *
 * @since 1.0
 *//*
function secupress_before_delete_consumer_email_option() {
	$old_email = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_email = isset( $old_email['consumer_email'] ) ? is_email( $old_email['consumer_email'] ) : false;
	secupress_cache_data( 'old_consumer_email', $old_email );
}


add_action( 'delete_site_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_deleted_consumer_email_option', 20 );
/**
 * If the consumer email address is deleted, trigger a custom event.
 *
 * @since 1.0
 *//*
function secupress_deleted_consumer_email_option() {
	$old_email = secupress_cache_data( 'old_consumer_email' );

	if ( $old_email ) {
		/**
		 * Fires after the consumer email has been deleted.
		 *
		 * @since 1.0
		 *
		 * @param (string) $old_email The old consumer email address.
		 *//*
		do_action( 'secupress.deleted-consumer_email', $old_email );
	}

	secupress_cache_data( 'old_consumer_email', null );
}
*/
