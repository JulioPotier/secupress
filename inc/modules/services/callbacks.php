<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* HALP!!! ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_services_settings_callback( $settings ) {
	global $wp_version;

	$modulenow = 'services';
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return array( 'sanitized' => 1 );
	}

	$allowed_tags = array(
		'a'      => array( 'href' => array(), 'title' => array(), 'target' => array() ),
		'abbr'   => array( 'title' => array() ),
		'code'   => array( 'class' => array() ),
		'em'     => array(),
		'strong' => array(),
		'ul'     => array(),
		'ol'     => array(),
		'li'     => array(),
		'p'      => array(),
		'pre'    => array( 'class' => array() ),
		'br'     => array(),
	);

	$settings = array_merge( array(
		'support_summary'     => '',
		'support_description' => '',
		'support_doc-read'    => 0,
		'support_scanner'     => '',
	), $settings );

	$summary     = trim( html_entity_decode( $settings['support_summary'], ENT_QUOTES ) );
	$summary     = strip_tags( wp_unslash( $summary ) );
	$summary     = preg_replace( "@[\r\n]+@", ' ', $summary );
	$description = trim( html_entity_decode( $settings['support_description'], ENT_QUOTES ) );
	$description = str_replace( "\r\n", "\n", wp_unslash( $description, ENT_QUOTES ) );

	$def_message = __( 'Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page', 'secupress' ) . "\n\n" .
	               __( 'Please let us know how we will recognize the issue or can reproduce the issue. What is supposed to happen, and what is actually happening instead?', 'secupress' );
	$def_message = str_replace( "\r\n", "\n", trim( html_entity_decode( $def_message, ENT_QUOTES ) ) );

	// Com'on, check it!
	if ( ! $settings['support_doc-read'] ) {
		$transient = array();

		if ( $summary ) {
			$transient['summary'] = $summary;
		}

		if ( $description && $def_message !== $description ) {
			$transient['description'] = $description;
		}

		if ( $transient ) {
			// Set a transient that will fill the fields back.
			set_site_transient( 'secupress_support_form', $transient, 300 );
		}

		add_settings_error( 'general', 'doc_read', __( 'Please check the checkbox first.', 'secupress' ) );

		return array( 'sanitized' => 1 );
	}

	// Other data.
	$data    = array();
	$scanner = sanitize_key( $settings['support_scanner'] );

	if ( $scanner ) {
		// Deal with the scanner.
		$scanners = secupress_get_scanners();
		$scanners = call_user_func_array( 'array_merge', $scanners );
		$scanners = array_combine( array_map( 'strtolower', $scanners ), $scanners );

		if ( ! empty( $scanners[ $scanner ] ) && file_exists( secupress_class_path( 'scan', $scanners[ $scanner ] ) ) ) {

			secupress_require_class( 'scan' );
			secupress_require_class( 'scan', $scanners[ $scanner ] );

			$class_name = 'SecuPress_Scan_' . $scanners[ $scanner ];
			$data       = array(
				'scanner' => sprintf( __( 'Scanner: %s', 'secupress' ), strip_tags( $class_name::get_instance()->title ) ),
			);
		}

		// Remove the scanner from the referer, we don't want it to be used for the redirection.
		if ( ! empty( $_REQUEST['_wp_http_referer'] ) ) {
			$_REQUEST['_wp_http_referer'] = str_replace( '&scanner=' . $scanner, '', $_REQUEST['_wp_http_referer'] );
		} else if ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			$_REQUEST['HTTP_REFERER'] = str_replace( '&scanner=' . $scanner, '', $_REQUEST['HTTP_REFERER'] );
		}
	}

	$data = array_merge( $data, array(
		'sp_free_version'   => sprintf( __( 'SecuPress Free Version: %s', 'secupress' ), SECUPRESS_VERSION ),
		'website_url'       => sprintf( __( 'Site URL: %s', 'secupress' ), esc_url( user_trailingslashit( home_url(), 'home' ) ) ),
		'is_multisite'      => sprintf( __( 'Multisite: %s', 'secupress' ), is_multisite() ? __( 'Yes', 'secupress' ) : __( 'No', 'secupress' ) ),
		'wp_version'        => sprintf( __( 'WordPress Version: %s', 'secupress' ), $wp_version ),
		'wp_active_plugins' => sprintf( __( 'Active plugins: %s', 'secupress' ), '<br/>- ' . implode( '<br/>- ', secupress_get_active_plugins() ) ),
	) );

	// Reset.
	$settings = array( 'sanitized' => 1 );
	delete_site_transient( 'secupress_support_form' );

	// Free plugin.
	if ( ! secupress_can_access_support() ) {
		$message = sprintf(
			/** Translators: %s is "plugin directory". */
			__( 'Oh, you are using SecuPress Free! The support is handled on the %s. Thank you!', 'secupress' ),
			'<a href="https://wordpress.org/support/plugin/secupress" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">' . __( 'plugin directory', 'secupress' ) . '</a>'
		);

		if ( $description && $def_message !== $description ) {
			if ( $summary ) {
				$message .= '</strong><br/>' . __( 'By the way, here is your subject:', 'secupress' ) . '</p>';
				$message .= '<blockquote>' . esc_html( $summary ) . '</blockquote>'; // Escaped.
				$message .= '<p>' . __( 'And your message:', 'secupress' ) . '</p>';
			} else {
				$message .= '</strong><br/>' . __( 'By the way, here is your message:', 'secupress' ) . '</p>';
			}

			// Sanitize and formate.
			$description  = wptexturize( $description );
			$description  = convert_chars( $description );
			$description  = wpautop( $description, false );
			$description  = preg_replace( '@<p\s*>(.*)</p>@', '\1<br/><br/>', $description );
			$description  = wp_kses( $description, $allowed_tags );
			$description .= '<br/>' . str_repeat( '-', 40 );
			$description .= '<br/>' . implode( '<br/>', $data );

			$message .= '<blockquote>' . $description . '</blockquote>';
			$message .= '<p>' . __( '(you\'re welcome)', 'secupress' ) . '<strong>';
		}

		add_settings_error( 'general', 'free_support', $message );

		return $settings;
	}

	// Pro plugin.
	if ( $summary && $description && $def_message !== $description ) {
		// Sanitize and formate.
		$description = wptexturize( $description );
		$description = convert_chars( $description );
		$description = wpautop( $description, false );
		$description = wp_kses( $description, $allowed_tags );

		/**
		 * Triggered when the user is asking for support.
		 *
		 * @since 1.0.6
		 *
		 * @param (string) $summary     A title. The value is not escaped.
		 * @param (string) $description A message. The value has been sanitized with `wp_kses()`.
		 * @param (array)  $data        An array of infos related to the site:
		 *                              - (string) $scanner           The scanner the user asks help for.
		 *                              - (string) $sp_free_version   Version of SecuPress Free.
		 *                              - (string) $website_url       Site URL.
		 *                              - (string) $is_multisite      Tell if it's a multisite: Yes or No.
		 *                              - (string) $wp_version        Version of WordPress.
		 *                              - (string) $wp_active_plugins List of active plugins.
		 */
		do_action( 'secupress.services.ask_for_support', $summary, $description, $data );
	} elseif ( ! $summary ) {
		// The summary is missing.
		add_settings_error( 'general', 'no_summary', __( 'Could you please give a short summary of your question?', 'secupress' ) );
	} elseif ( ! $description ) {
		// The message is missing.
		add_settings_error( 'general', 'no_description', __( 'Without any description, it will be difficult to bring your help.', 'secupress' ) );
	} else {
		// The message is the default one.
		add_settings_error( 'general', 'default_description', __( 'I don\'t think this description can be of any help.', 'secupress' ) );
	}

	return $settings;
}


add_action( 'secupress.services.ask_for_support', 'secupress_send_support_request', 10, 3 );
/**
 * Send an email message to our awesome support team (yes it is).
 *
 * @since 1.1.1
 * @author Grégory Viguier
 *
 * @param (string) $summary     A title. The value is not escaped.
 * @param (string) $description A message. The value has been sanitized with `wp_kses()`.
 * @param (array)  $data        An array of infos related to the site:
 *                              - (string) $scanner           The scanner the user asks help for.
 *                              - (string) $sp_free_version   Version of SecuPress Free.
 *                              - (string) $website_url       Site URL.
 *                              - (string) $is_multisite      Tell if it's a multisite: Yes or No.
 *                              - (string) $wp_version        Version of WordPress.
 *                              - (string) $wp_active_plugins List of active plugins.
 */
function secupress_send_support_request( $summary, $description, $data ) {
	// To.
	$to = strrev( 'em' . '.' . 'sserpuces' . chr( 64 ) . 'troppus' );

	// From.
	$from_user = wp_get_current_user();
	$from      = secupress_get_user_full_name( $from_user ) . ' <' . $from_user->data->user_email . '>';

	// Headers.
	$headers = array(
		'from: ' . $from,
		'content-type: text/html',
	);

	// Subject.
	$summary = esc_html( $summary );
	if ( function_exists( 'mb_convert_encoding' ) ) {
		$summary = preg_replace_callback( '/(&#[0-9]+;)/', function( $m ) {
			return mb_convert_encoding( $m[1], 'UTF-8', 'HTML-ENTITIES' );
		}, $summary );
	}
	$summary = wp_specialchars_decode( $summary );

	// Message.
	$data = array_merge( array(
		'license_email'  => sprintf( __( 'License email: %s', 'secupress' ), secupress_get_consumer_email() ),
		'license_key'    => sprintf( __( 'License key: %s', 'secupress' ), secupress_get_consumer_key() ),
		'sp_pro_version' => secupress_has_pro() ? sprintf( __( 'Version of SecuPress Pro: %1$s (requires SecuPress Free %2$s)', 'secupress' ), SECUPRESS_PRO_VERSION, SECUPRESS_PRO_SECUPRESS_MIN ) : __( 'Version of SecuPress Pro: inactive', 'secupress' ),
	), $data );

	$data = '<br/>' . str_repeat( '-', 40 ) . '<br/>' . implode( '<br/>', $data );

	// Go!
	$success = wp_mail( $to, $summary, $description . $data, $headers );

	if ( $success ) {
		add_settings_error( 'general', 'message_sent', __( 'Your message has been sent, we will come back to you shortly. Thank you.', 'secupress' ), 'updated' );
	} else {
		$summary     = str_replace( '+', '%20', urlencode( $summary ) );
		$description = str_replace( array( '+', '%3E%0A' ), array( '%20', '%3E' ), urlencode( $description . $data ) );
		$url         = 'mailto:' . $to . '?subject=' . $summary . '&body=' . $description;

		add_settings_error( 'general', 'message_failed', sprintf(
			/** Translators: %s is an email address. */
			__( 'Something prevented your message to be sent. Please send it manually to %s. Thank you.', 'secupress' ),
			'<a href="' . esc_url( $url ) . '">' . $to . '</a>'
		) );
	}
}


/**
 * Get a user name.
 * Try first to have first name + last name, then only first name or last name, then only last name or first name, then display name.
 *
 * @since 1.1.1
 * @author Grégory Viguier
 *
 * @param $user (object) A WP_User object.
 *
 * @return (string)
 */
function secupress_get_user_full_name( $user ) {
	if ( ! empty( $user->first_name ) && ! empty( $user->last_name ) ) {
		return sprintf( _x( '%1$s %2$s', 'User full name. 1: first name, 2: last name', 'secupress' ), $user->first_name, $user->last_name );
	}

	$field1 = sprintf( _x( '%1$s %2$s', 'User full name. 1: first name, 2: last name', 'secupress' ), 'first_name', 'last_name' );

	if ( strpos( $field1, 'first_name' ) < strpos( $field1, 'last_name' ) ) {
		$field1 = 'first_name';
		$field2 = 'last_name';
	} else {
		$field1 = 'last_name';
		$field2 = 'first_name';
	}

	if ( ! empty( $user->$field1 ) ) {
		return $user->$field1;
	}

	if ( ! empty( $user->$field2 ) ) {
		return $user->$field2;
	}

	return $user->display_name;
}


/**
 * Get name & version of all active plugins.
 *
 * @since 1.0.6
 * @author Grégory Viguier
 *
 * @return (array) An array of active plugins: name and version.
 */
function secupress_get_active_plugins() {
	$all_plugins    = get_plugins();
	$active_plugins = array();

	if ( is_multisite() ) {
		// Get network activated plugins.
		$network_plugins = array_filter( (array) get_site_option( 'active_sitewide_plugins', array() ) );
		$network_plugins = array_intersect_key( $all_plugins, $network_plugins );

		if ( $network_plugins ) {
			foreach ( $network_plugins as $plugin ) {
				$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'network', 'secupress' ) . ')';
			}
		}

		// Get blog activated plugins.
		$plugins = get_site_option( 'secupress_active_plugins' );

		if ( is_array( $plugins ) ) {
			// We can use our option that stores all blog activated plugins.
			$plugins = call_user_func_array( 'array_merge', $plugins ); // The plugin paths are the array keys.
			$plugins = array_diff_key( $plugins, $network_plugins );    // Make sure we don't have network activated plugins in the list.
			$plugins = array_intersect_key( $all_plugins, $plugins );

			if ( $plugins ) {
				foreach ( $plugins as $plugin ) {
					$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'];
				}
			}
		} else {
			// At least, get the plugins active on the main blog.
			$plugins = array_diff_key( $all_plugins, $network_plugins ); // Remove network activated plugins.
			$plugins = array_intersect_key( $all_plugins, array_flip( array_filter( array_keys( $plugins ), 'is_plugin_active' ) ) );

			if ( $plugins ) {
				foreach ( $plugins as $plugin ) {
					$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'main site', 'secupress' ) . ')';
				}
			}
		}
	} else {
		// Not a multisite.
		$plugins = array_intersect_key( $all_plugins, array_flip( array_filter( array_keys( $all_plugins ), 'is_plugin_active' ) ) );

		if ( $plugins ) {
			foreach ( $plugins as $plugin ) {
				$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'];
			}
		}
	}

	// Must-Use plugins.
	$plugins = get_mu_plugins();

	if ( $plugins ) {
		foreach ( $plugins as $plugin ) {
			$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'Must-Use plugin', 'secupress' ) . ')';
		}
	}

	// Drop-ins.
	$plugins = get_dropins();

	if ( $plugins ) {
		foreach ( $plugins as $plugin ) {
			/** Translators: a drop-in is specific kind of WordPress plugin. */
			$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'drop-in', 'secupress' ) . ')';
		}
	}

	return $active_plugins;
}
