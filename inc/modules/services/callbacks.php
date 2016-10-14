<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
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

	$summary     = preg_replace( "@[\r\n]+@", ' ', strip_tags( wp_unslash( trim( html_entity_decode( $settings['support_summary'], ENT_QUOTES ) ) ) ) );
	$description = str_replace( "\r\n", "\n", wp_unslash( trim( html_entity_decode( $settings['support_description'], ENT_QUOTES ) ) ) );

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
		'sp_free_version'   => sprintf( __( 'Version of SecuPress Free: %s', 'secupress' ), SECUPRESS_VERSION ),
		'website_url'       => sprintf( __( 'Site URL: %s', 'secupress' ), esc_url( user_trailingslashit( home_url(), 'home' ) ) ),
		'is_multisite'      => sprintf( __( 'Multisite: %s', 'secupress' ), is_multisite() ? __( 'Yes', 'secupress' ) : __( 'No', 'secupress' ) ),
		'wp_version'        => sprintf( __( 'Version of WordPress: %s', 'secupress' ), $wp_version ),
		'wp_active_plugins' => sprintf( __( 'Active plugins: %s', 'secupress' ), "\n- " . implode( "\n- ", secupress_get_active_plugins() ) ),
	) );

	// Reset.
	$settings = array( 'sanitized' => 1 );
	delete_site_transient( 'secupress_support_form' );

	// Free plugin.
	if ( ! secupress_is_pro() ) {
		$message = sprintf(
			/** Translators: 1 is the plugin name, 2 is a link to the "plugin directory". */
			__( 'Oh, you use the Free version of %1$s! Support is handled on the %2$s. Thank you!', 'secupress' ),
			SECUPRESS_PLUGIN_NAME,
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
			$description  = wpautop( $description );
			$description  = wp_kses( $description, $allowed_tags );
			$description .= '<br/><br/>' . str_repeat( '-', 40 );
			$description .= '<br/>' . implode( '<br/>', $data );

			$message .= '<blockquote>' . esc_html( $description ) . '</blockquote>'; // Escaped.
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
		$description = wpautop( $description );
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
		add_settings_error( 'general', 'no_summary', __( 'Could you please give a short summary of your problem?', 'secupress' ) );
	} elseif ( ! $description ) {
		// The message is missing.
		add_settings_error( 'general', 'no_description', __( 'Without any description, it will be difficult to solve your problem.', 'secupress' ) );
	} else {
		// The message is the default one.
		add_settings_error( 'general', 'default_description', __( 'I don\'t think this description can be of any help.', 'secupress' ) );
	}

	return $settings;
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
