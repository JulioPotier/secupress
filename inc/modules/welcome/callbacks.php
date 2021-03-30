<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** CALLBACKS FOR THE MAIN SETTINGS =========================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Deal with the dashboard page.
 *
 * @since 1.4.3
 * @author Julio Potier
 */
function secupress_welcome_settings_callback( $settings ) {
	$modulenow = 'welcome';
	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_welcome_settings-options' );

	$_FILES = apply_filters( 'wp_handle_upload_prefilter', $_FILES );

	// Handle Import.
	if ( ! empty( $_FILES['import'] ) ) {
		secupress_settings_import_callback();
		return $settings;
	}

	// Handle White Label.
	if ( secupress_is_pro() && isset( $_POST['secupress_display_white_label_submit'], $_POST['secupress_welcome_settings'] ) ) {
		secupress_pro_settings_white_label_callback();
		return $settings;
	}

	// Handle License.
	if ( isset( $_POST['secupress_display_apikey_options_submit'] ) ) {
		secupress_settings_licence_callback();
		return $settings;
	}

	if ( ! isset( $settings['advanced-settings_admin-bar'] ) ) {
		$settings['advanced-settings_admin-bar'] = '0';
	}
	if ( ! isset( $settings['advanced-settings_grade-system'] ) ) {
		$settings['advanced-settings_grade-system'] = '0';
	}
	if ( ! isset( $settings['advanced-settings_expert-mode'] ) ) {
		$settings['advanced-settings_expert-mode'] = '0';
	}
	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, null );

	return $settings;
}


/**
 * Deal with the License
 *
 * @since 1.0.3
 * @author Gregory Viguier
 */
function secupress_settings_licence_callback() {
	$old_values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_values = is_array( $old_values ) ? $old_values : array();
	$old_email  = ! empty( $old_values['consumer_email'] ) ? sanitize_email( $old_values['consumer_email'] )    : '';
	$old_key    = ! empty( $old_values['consumer_key'] )   ? sanitize_text_field( $old_values['consumer_key'] ) : '';
	$old_is_pro = ! empty( $old_values['site_is_pro'] )    ? 1 : 0;
	$has_old    = $old_email && $old_key;
	$old_email  = $has_old ? $old_email  : '';
	$old_key    = $has_old ? $old_key    : '';
	$old_is_pro = $has_old ? $old_is_pro : 0;
	unset( $old_values['sanitized'] ); // Back compat'.
	// New values.
	$values     = ! empty( $_POST['secupress_welcome_settings'] ) && is_array( $_POST['secupress_welcome_settings'] ) ? $_POST['secupress_welcome_settings'] : array(); // WPCS: CSRF ok.
	$values     = secupress_array_merge_intersect( $values, array(
		'consumer_email' => '',
		'consumer_key'   => '',
	) );
	$values['install_time'] = ! empty( $old_values['install_time'] ) ? (int) $old_values['install_time'] : time();
	$new_email  = $values['consumer_email'] ? sanitize_email( $values['consumer_email'] )    : '';
	$new_key    = $values['consumer_key']   ? sanitize_text_field( $values['consumer_key'] ) : '';
	$has_new    = $new_email && $new_key;
	$new_email  = $has_new ? $new_email : '';
	$new_key    = $has_new ? $new_key   : '';
	// Action.
	$action     = $has_old && $old_is_pro ? 'deactivate' : 'activate';

	if ( 'deactivate' === $action ) {
		// To deactivate, use old values.
		$values['consumer_email'] = $old_email;
		$values['consumer_key']   = $old_key;
	}
	elseif ( $has_new ) {
		// To activate, use new values.
		$values['consumer_email'] = $new_email;
		$values['consumer_key']   = $new_key;
	}
	else {
		// PEBCAK, new values are not good.
		$action = false;

		if ( ! $values['consumer_email'] && ! $values['consumer_key'] ) {
			secupress_add_settings_error( 'general', 'no_email_license', secupress_global_settings_pro_license_activation_error_message( 'no_email_license' ) );
		} elseif ( ! $values['consumer_email'] ) {
			secupress_add_settings_error( 'general', 'no_email', secupress_global_settings_pro_license_activation_error_message( 'no_email' ) );
		} else {
			secupress_add_settings_error( 'general', 'no_license', secupress_global_settings_pro_license_activation_error_message( 'no_license' ) );
		}

		if ( $has_old ) {
			// Send the previous values back.
			$values['consumer_email'] = $old_email;
			$values['consumer_key']   = $old_key;

			if ( $old_is_pro ) {
				$values['site_is_pro'] = 1;
			}
		} else {
			// Empty the new values.
			unset( $values['consumer_email'], $values['consumer_key'] );
		}
	}

	if ( 'deactivate' === $action ) {
		// Deactivate the license.
		$values = secupress_global_settings_deactivate_pro_license( $values );
	} elseif ( 'activate' === $action ) {
		// Activate the license.
		$values = secupress_global_settings_activate_pro_license( $values, $old_values );

		if ( empty( $values['site_is_pro'] ) && ! secupress_get_settings_errors( 'general' ) ) {
			// Invalid key.
			secupress_add_settings_error( 'general', 'invalid_license', secupress_global_settings_pro_license_activation_error_message( 'invalid_license' ) );
		}
	}

	// Remove previous values.
	unset( $old_values['consumer_email'], $old_values['consumer_key'], $old_values['site_is_pro'] );

	// Add other previous values.
	$values = array_merge( $old_values, $values );

	// Finally, save.
	secupress_update_options( $values );

	/**
	 * Handle settings errors and return to settings page.
	 */
	// If no settings errors were registered add a general 'updated' message.
	if ( ! secupress_get_settings_errors( 'general' ) ) {
		if ( 'deactivate' === $action ) {
			secupress_add_settings_error( 'general', 'settings_updated', __( 'Your license has been successfully deactivated.', 'secupress' ), 'updated' );
		} elseif ( 'activate' === $action ) {
			secupress_add_settings_error( 'general', 'settings_updated', __( 'Your license has been successfully activated.', 'secupress' ), 'updated' );
		}
	}
	set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

	/**
	 * Redirect back to the settings page that was submitted.
	 */
	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( esc_url_raw( $goback ) );
	exit;
}

/**
 * Handle the white label validation
 *
 * @since 1.4.5
 * @author Julio Potier
 **/
function secupress_pro_settings_white_label_callback() {
	$old_values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_values = is_array( $old_values ) ? $old_values : [];
	$names      = [
			'wl_plugin_name' => '',
			'wl_plugin_URI'  => '',
			'wl_description' => '',
			'wl_author'      => '',
			'wl_author_URI'  => '',
		];
	// New values.
	$values     = $_POST['secupress_welcome_settings']; // WPCS: CSRF ok.
	// Some cleanup.
	if ( empty( $values['wl_plugin_name'] ) || '' === trim( $values['wl_plugin_name'] ) ) {
		$values = $names;
	} else {
		$values = wp_parse_args( $values, $names );
	}

	// White Label: trick the referer for the redirection.
	$old_slug = 'page=' . SECUPRESS_PLUGIN_SLUG . '_modules';
	$new_slug = 'page=' . sanitize_title( $values['wl_plugin_name'] ) . '_modules';

	if ( '' !== $values['wl_plugin_name'] ) {
		$values = wp_parse_args( $values, $old_values );
	} else {
		$new_slug = 'page=secupress_modules';
		$values = wp_parse_args( $values, $old_values );
		foreach ( $names as $name => $dummy ) {
			unset( $values[ $name ] );
		}
	}

	if ( $old_slug !== $new_slug ) {
		$_REQUEST['_wp_http_referer'] = str_replace( $old_slug, $new_slug, wp_get_raw_referer() );
		secupress_add_settings_error( 'general', 'settings_updated', __( 'Plugin has been renamed correctly.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );
	}

	// Finally, save.
	secupress_update_options( $values );

	/**
	 * Redirect back to the settings page that was submitted.
	 */
	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( esc_url_raw( $goback ) );
	exit;
}
/**
 * Call our server to activate the Pro license.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $new_values The new settings.
 * @param (array) $old_values The old settings.
 *
 * @return (array) $new_values The new settings, some values may have changed.
 */
function secupress_global_settings_activate_pro_license( $new_values, $old_values = array() ) {
	// If the Pro is not installed, get the plugin information.
	$need_plugin_data = (int) ! secupress_has_pro();
	$api_old_values   = secupress_array_merge_intersect( $old_values, array(
		'consumer_email' => '',
		'consumer_key'   => '',
		'site_is_pro'    => 0,
		'install_time'   => 0,
	) );
	unset( $new_values['license_error'] );

	if ( $new_values['install_time'] > 1 ) {
		$install_time = time() - $new_values['install_time'];
	} elseif ( -1 !== $new_values['install_time'] ) {
		$install_time = 0;
	} else {
		$install_time = -1;
	}

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'    => 'activate_pro_license',
		'user_email'   => $new_values['consumer_email'],
		'user_key'     => $new_values['consumer_key'],
		'install_time' => $install_time,
		'plugin_data'  => $need_plugin_data,
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( $body = secupress_global_settings_api_request_succeeded( $response ) ) {
		// Success!
		$new_values['install_time'] = -1;
		$new_values['consumer_key'] = sanitize_text_field( $body->data->user_key );

		if ( ! empty( $body->data->site_is_pro ) ) {
			$new_values['site_is_pro'] = 1;

			if ( ! empty( $body->data->plugin_information ) ) {
				// Store the plugin information. See `SecuPress_Admin_Pro_Upgrade::maybe_warn_to_install_pro_version()`.
				SecuPress_Admin_Pro_Upgrade::get_instance()->maybe_set_transient_from_remote( $body->data->plugin_information );
			} elseif ( $need_plugin_data ) {
				// Should not happen.
				SecuPress_Admin_Pro_Upgrade::get_instance()->delete_transient();
			}
		} else {
			unset( $new_values['site_is_pro'] );

			if ( $need_plugin_data ) {
				SecuPress_Admin_Pro_Upgrade::get_instance()->delete_transient();
			}
		}
	} else {
		// Keep old values.
		if ( $api_old_values['consumer_email'] && $api_old_values['consumer_key'] ) {
			$new_values['consumer_email'] = $api_old_values['consumer_email'];
			$new_values['consumer_key']   = $api_old_values['consumer_key'];
		}

		if ( ! $new_values['consumer_email'] || ! $new_values['consumer_key'] ) {
			unset( $new_values['consumer_email'], $new_values['consumer_key'], $new_values['site_is_pro'] );
		} elseif ( $api_old_values['site_is_pro'] ) {
			// Don't invalidate the license because we couldn't reach our server or things like that.
			$new_values['site_is_pro'] = 1;
		} else {
			unset( $new_values['site_is_pro'] );
		}

		if ( secupress_has_pro() ) {
			// Invalidate the license only for some reasons.
			$errors = secupress_get_settings_errors( 'general' );

			if ( $errors ) {
				$codes = secupress_global_settings_pro_license_activation_error_message( 'edd' );

				foreach ( $errors as $error ) {
					if ( isset( $codes[ $error['code'] ] ) ) {
						unset( $new_values['site_is_pro'] );
						$new_values['license_error'] = $error['code'];
						break;
					}
				}
			}
		}

		if ( $need_plugin_data ) {
			SecuPress_Admin_Pro_Upgrade::get_instance()->delete_transient();
		}
	}

	// Triggered by auto license validation.
	if ( empty( $old_values ) ) {
		$options = get_site_option( SECUPRESS_SETTINGS_SLUG ) ? get_site_option( SECUPRESS_SETTINGS_SLUG ) : array();
		update_site_option( SECUPRESS_SETTINGS_SLUG, array_merge( $new_values, $options ) );
	} else {
		return $new_values;
	}
}


/**
 * Trigger a settings error if the given API request failed.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (mixed) $response The request response.
 *
 * @return (object|bool) The response body on success. False otherwise.
 */
function secupress_global_settings_api_request_succeeded( $response ) {

	if ( is_wp_error( $response ) ) {
		$listMessages = '';
		foreach($response->get_error_messages() as $message) {
			$listMessages = $listMessages . ' - ' . $message;
		}

		// The request couldn't be sent.
		secupress_add_settings_error( 'general', 'request_error', secupress_global_settings_pro_license_activation_error_message( 'request_error' ) . $listMessages );
		return false;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		// The server couldn't be reached. Maybe a server error or something.
		secupress_add_settings_error( 'general', 'server_error', secupress_global_settings_pro_license_activation_error_message( 'server_error' ) );
		return false;
	}

	$body = wp_remote_retrieve_body( $response );
	$body = @json_decode( $body );

	if ( ! is_object( $body ) ) {
		// The response is not a json.
		secupress_add_settings_error( 'general', 'server_bad_response', secupress_global_settings_pro_license_activation_error_message( 'server_bad_response' ) );
		return false;
	}

	if ( empty( $body->success ) ) {
		// The response is an error.
		if ( ! empty( $body->data->error ) ) {
			secupress_add_settings_error( 'general', $body->data->error, secupress_global_settings_pro_license_activation_error_message( $body->data->error ) );
		} elseif ( ! empty( $body->data->code ) ) {
			secupress_add_settings_error( 'general', $body->data->code, secupress_global_settings_pro_license_activation_error_message( $body->data->code ) );
		} else {
			secupress_add_settings_error( 'general', 'license_error', secupress_global_settings_pro_license_activation_error_message( 'license_error' ) );
		}

		return false;
	}

	return $body;
}


/**
 * Get an error message or an array of error messages.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (string) $code     An error code. Return an array of messages if 'all', 'api', or 'edd'. The 'edd' value returns the messages that should trigger a license invalidation.
 * @param (string) $fallback The error code corresponding to the default message to return if the given $code doesn't match any of the error codes.
 *
 * @return (array|string) An error message or an array of error messages.
 */
function secupress_global_settings_pro_license_activation_error_message( $code = false, $fallback = 'license_error' ) {
	$support_link = '<a href="' . esc_url( SecuPress_Admin_Offer_Migration::get_support_url() ) . '" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">' . __( 'our support team', 'secupress' ) . '</a>';
	$account_link = '<a href="' . esc_url( SecuPress_Admin_Offer_Migration::get_account_url() ) . '" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">%s</a>';

	$api_errors = array(
		'no_email_license'    => __( 'Please provide a valid email address and your license key.', 'secupress' ),
		'no_email'            => __( 'Please provide a valid email address.', 'secupress' ),
		'no_license'          => __( 'Please provide your license key.', 'secupress' ),
		'invalid_license'     => sprintf(
			/** Translators: %s is a "to verify these infos" link. */
			__( 'Your license key seems invalid. You may want %s.', 'secupress' ),
			sprintf( $account_link, __( 'to verify these infos', 'secupress' ) )
		),
		'request_error'       => __( 'Something on your website is preventing the request to be sent.', 'secupress' ),
		/** Translators: %s is a "our support team" link. */
		'server_error'        => sprintf( __( 'Our server is not accessible at the moment, please try again later or contact %s.', 'secupress' ), $support_link ),
		/** Translators: %s is a "our support team" link. */
		'server_bad_response' => sprintf( __( 'Our server returned an unexpected response and might be in error, please try again later or contact %s.', 'secupress' ), $support_link ),
		/** Translators: %s is a "our support team" link. */
		'invalid_api_request' => sprintf( __( 'There is a problem with your license key, please contact %s.', 'secupress' ), $support_link ),
		'invalid_email'       => __( 'The email address is invalid.', 'secupress' ),
		'invalid_license_key' => __( 'The license key is invalid.', 'secupress' ),
		'invalid_customer'    => sprintf(
			/** Translators: %s is a "to verify these infos" link. */
			__( 'This email address is not in our database. You may want %s.', 'secupress' ),
			sprintf( $account_link, __( 'to verify these infos', 'secupress' ) )
		),
	);

	if ( 'api' === $code ) {
		return $api_errors;
	}

	// These are errors returned by EDD and that may (or not) require SecuPress Pro uninstall.
	$edd_errors = array(
		/** Translators: %s is a "our support team" link. */
		'missing'             => sprintf( __( 'There is a problem with your license key, please verify it. If you think there is a mistake, you should contact %s.', 'secupress' ), $support_link ),
		/** Translators: %s is a "our support team" link. */
		'key_mismatch'        => sprintf( __( 'There is a problem with your license key, please verify it. If you think there is a mistake, you should contact %s.', 'secupress' ), $support_link ),
		/** Translators: %s is a "our support team" link. */
		'revoked'             => sprintf( __( 'This license key has been revoked. If you think there is a mistake, you should contact %s.', 'secupress' ), $support_link ),
		'expired'             => sprintf(
			/** Translators: %s is a "to renew your subscription" link. */
			__( 'This license key expired. You may want %s.', 'secupress' ),
			sprintf( $account_link, __( 'to renew your subscription', 'secupress' ) )
		),
		'no_activations_left' => sprintf(
			/** Translators: %s is a "to upgrade your license" link. */
			__( 'You used as many sites as your license allows. You may want %s to add more sites.', 'secupress' ),
			sprintf( $account_link, __( 'to upgrade your license', 'secupress' ) )
		),
	);

	if ( 'edd' === $code ) {
		return $edd_errors;
	}

	$all_errors = array_merge( $api_errors, $edd_errors );

	// Generic message.
	$all_errors['license_error'] = sprintf(
		/** Translators: 1 is a "your account" link, 2 is a "our support team" link. */
		__( 'Something may be wrong with your license, please take a look at %1$s or contact %2$s.', 'secupress' ),
		sprintf( $account_link, __( 'your account', 'secupress' ) ),
		$support_link
	);

	if ( 'all' === $code ) {
		return $all_errors;
	}

	if ( ! empty( $all_errors[ $code ] ) ) {
		return $all_errors[ $code ];
	}

	return ! empty( $all_errors[ $fallback ] ) ? $all_errors[ $fallback ] : $all_errors['license_error'];
}


/**
 * Call our server to deactivate the Pro license.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (array) $new_values The new settings.
 *
 * @return (array) $new_values The new settings, the email and the key have been removed.
 */
function secupress_global_settings_deactivate_pro_license( $new_values ) {

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'    => 'deactivate_pro_license',
		'user_email'   => $new_values['consumer_email'],
		'user_key'     => $new_values['consumer_key'],
	) );

	unset( $new_values['consumer_email'], $new_values['consumer_key'] );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( is_wp_error( $response ) ) {
		// The request couldn't be sent.
		$message = __( 'Something on your website is preventing the request to be sent.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		secupress_add_settings_error( 'general', 'request_error', $message );
		return $new_values;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		// The server couldn't be reached. Maybe a server error or something.
		$message = __( 'Our server is not accessible at the moment.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		secupress_add_settings_error( 'general', 'server_error', $message );
		return $new_values;
	}

	$body = wp_remote_retrieve_body( $response );
	$body = @json_decode( $body );

	if ( ! is_object( $body ) ) {
		// The response is not a json.
		$message = __( 'Our server returned an unexpected response and might be in error.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		secupress_add_settings_error( 'general', 'server_bad_response', $message );
		return $new_values;
	}

	if ( empty( $body->success ) ) {
		// Didn't succeed.
		$message = __( 'Our server returned an error.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		secupress_add_settings_error( 'general', 'response_error', $message );
	}

	return $new_values;
}


/**
 * Given a message, add a sentense to it with a link to the user account on our website.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (string) $message The message with a link to our website appended.
 */
function secupress_global_settings_pro_license_deactivation_error_message( $message ) {
	if ( secupress_is_white_label() ) {
		// White-labelled, don't add a link to our website.
		return $message;
	}

	$secupress_message = sprintf(
		/** Translators: %s is a link to the "SecuPress account". */
		__( 'Please deactivate this site from your %s (the "Manage Sites" link in your license details).', 'secupress' ),
		'<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . esc_url( SecuPress_Admin_Offer_Migration::get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
	);

	if ( is_rtl() ) {
		$message = $secupress_message . ' ' . $message;
	} else {
		$message .= ' ' . $secupress_message;
	}

	return $message;
}
