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
function __secupress_global_settings_callback( $value ) {
	$value = $value ? $value : array();

	if ( isset( $value['sanitized'] ) ) {
		return $value;
	}
	$value['sanitized'] = 1;

	// Previous values.
	$old_value = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_value = is_array( $old_value ) ? $old_value : array();

	// API and license validation.
	$value['consumer_email'] = ! empty( $value['consumer_email'] ) ? is_email( $value['consumer_email'] )          : '';
	$value['consumer_key']   = ! empty( $value['consumer_key'] )   ? sanitize_text_field( $value['consumer_key'] ) : '';	// Free API key, the user key.

	// We have a valid email address: add the site.
	if ( $value['consumer_email'] ) {
		// Call home.
		$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
			'sp_action'   => 'update_subscription',
			'user_email'  => $value['consumer_email'],
			'user_key'    => $value['consumer_key'],
			'plugin_name' => ! empty( $value['wl_plugin_name'] ) && secupress_is_pro() ? $value['wl_plugin_name'] : 'SecuPress',
		) );

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {

			// The request couldn't be sent.
			add_settings_error( 'secupress_global', 'request_error', __( 'Something on your website is preventing the request to be sent.', 'secupress' ) );

		} elseif ( 200 !== wp_remote_retrieve_response_code( $response ) ) {

			// The server couldn't be reached. Maybe a server error or something.
			add_settings_error( 'secupress_global', 'server_error', __( 'Our server is not reachable at the moment, please try again later.', 'secupress' ) );

		} else {
			$body = wp_remote_retrieve_body( $response );
			$body = @json_decode( $body );

			if ( ! is_object( $body ) ) {

				// The response is not a json.
				add_settings_error( 'secupress_global', 'server_bad_response', __( 'Our server returned an unexpected response and might be in error, please try again later or contact our support team.', 'secupress' ) );

			} elseif ( empty( $body->success ) ) {

				// The response is an error.
				if ( 'invalid_api_credential' === $body->data->code ) {

					add_settings_error( 'secupress_global', 'response_error', __( 'There is a problem with your API key, please contact our support team to reset it.', 'secupress' ) );
					unset( $value['consumer_key'], $value['site_is_pro'] );

				} else {
					add_settings_error( 'secupress_global', 'response_error', __( 'Our server returned an error, please try again later or contact our support team.', 'secupress' ) );
				}

			} else {
				// Success.
				$value['consumer_key'] = sanitize_text_field( $body->data->user_key );
				$value['site_is_pro']  = (int) ! empty( $body->data->site_is_pro );
			}
		}
	}
	// No valid email: remove the site.
	else {
		// Make sure everything's fine before deleting values.
		$value['consumer_email'] = $old_value['consumer_email'];
		$value['consumer_key']   = $old_value['consumer_key'];

		// Call home.
		$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
			'sp_action'   => 'remove_subscription',
			'user_email'  => $value['consumer_email'],
			'user_key'    => $value['consumer_key'],
		) );

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {

			// The request couldn't be sent.
			add_settings_error( 'secupress_global', 'request_error', __( 'Something on your website is preventing the request to be sent.', 'secupress' ) );

		} elseif ( 200 !== wp_remote_retrieve_response_code( $response ) ) {

			// The server couldn't be reached. Maybe a server error or something.
			add_settings_error( 'secupress_global', 'server_error', __( 'Our server is not reachable at the moment, please try again later.', 'secupress' ) );

		} else {
			$body = wp_remote_retrieve_body( $response );
			$body = @json_decode( $body );

			if ( ! is_object( $body ) ) {

				// The response is not a json.
				add_settings_error( 'secupress_global', 'server_bad_response', __( 'Our server returned an unexpected response and might be in error, please try again later or contact our support team.', 'secupress' ) );

			} elseif ( empty( $body->success ) ) {

				// The response is an error.
				if ( 'invalid_api_credential' === $body->data->code ) {

					add_settings_error( 'secupress_global', 'response_error', __( 'There is a problem with your API key, please contact our support team to reset it.', 'secupress' ) );
					unset( $value['consumer_key'], $value['site_is_pro'] );

				} else {
					add_settings_error( 'secupress_global', 'response_error', __( 'Our server returned an error, please try again later or contact our support team.', 'secupress' ) );
				}

			} else {
				// Success.
				unset( $value['consumer_email'], $value['consumer_key'], $value['site_is_pro'] );
			}
		}
	}

	// Uptime monitor.
	if ( ! empty( $old_value['uptime_monitoring_account_key'] ) && ! empty( $old_value['uptime_monitoring_site_key'] ) ) {
		$value['uptime_monitoring_account_key'] = $old_value['uptime_monitoring_account_key'];
		$value['uptime_monitoring_site_key']    = $old_value['uptime_monitoring_site_key'];
	} else {
		unset( $value['uptime_monitoring_account_key'], $value['uptime_monitoring_site_key'] );
	}

	return $value;
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


/*------------------------------------------------------------------------------------------------*/
/* TRACK CHANGES IN CONSUMER EMAIL ============================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'add_site_option_' . SECUPRESS_SETTINGS_SLUG,    'secupress_updated_consumer_email_option', 20, 2 );
add_action( 'update_site_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_updated_consumer_email_option', 20, 3 );
/**
 * If the consumer email address is changed, trigger a custom event.
 *
 * @since 1.0
 *
 * @param (string) $option   Name of the option.
 * @param (mixed)  $newvalue The new value of the option.
 * @param (mixed)  $oldvalue The old value of the option.
 */
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
		 */
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
		 */
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
		 */
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
 */
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
 */
function secupress_deleted_consumer_email_option() {
	$old_email = secupress_cache_data( 'old_consumer_email' );

	if ( $old_email ) {
		/**
		 * Fires after the consumer email has been deleted.
		 *
		 * @since 1.0
		 *
		 * @param (string) $old_email The old consumer email address.
		 */
		do_action( 'secupress.deleted-consumer_email', $old_email );
	}

	secupress_cache_data( 'old_consumer_email', null );
}