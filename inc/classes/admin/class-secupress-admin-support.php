<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Admin support class.
 *
 * @package SecuPress
 * @since 1.1.4
 * @author Grégory Viguier
 */
class SecuPress_Admin_Support {

	const VERSION = '1.1';
	/**
	 * The data sent by the user.
	 *
	 * @var (array)
	 */
	protected $settings;
	/**
	 * The request summary.
	 *
	 * @var (string)
	 */
	protected $summary;
	/**
	 * The request description.
	 *
	 * @var (string)
	 */
	protected $description;
	/**
	 * The request scanner (the user asked for support from the step 3 of the scanner).
	 *
	 * @var (string)
	 */
	protected $scanner;
	/**
	 * The data about the license, the site, etc.
	 *
	 * @var (array)
	 */
	protected $data;


	/** Public methods ========================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @param (array) $settings An array containing the data sent by the user.
	 */
	public function __construct( $settings ) {
		// Set the data sent by the user.
		$this->settings = array_merge( array(
			'support_summary'     => '',
			'support_description' => '',
			'support_scanner'     => '',
			'support_doc-read'    => 0,
		), $settings );

		// The checkbox is mandatory.
		if ( ! $this->settings['support_doc-read'] ) {
			$this->display_checkbox_message();
			return;
		}

		// Make sure to reset the form.
		delete_site_transient( 'secupress_support_form' );

		// Free plugin.
		if ( ! secupress_can_access_support() ) {
			$this->display_free_plugin_message();
			return;
		}

		// Pro plugin.
		if ( $this->get_summary() && $this->has_description() ) {
			$summary     = $this->get_summary();
			$data        = $this->get_data();
			// Sanitize and formate.
			$description = wptexturize( $this->get_description() );
			$description = convert_chars( $description );
			$description = wpautop( $description, false );
			$description = wp_kses( $description, static::get_allowed_tags() );

			/**
			 * Triggered when the user is asking for support.
			 *
			 * @since 1.0.6
			 * @since 1.1.4 Some data names changed.
			 *
			 * @param (string) $summary     A title. The value is not escaped.
			 * @param (string) $description A message. The value has been sanitized with `wp_kses()`.
			 * @param (array)  $data        An array of infos related to the site:
			 *                              // Support request.
			 *                                 - (string) $support_scanner   The title of the scanner the user asks help for.
			 *                              // License.
			 *                                 - (string) $license_email     The email adress used for the license.
			 *                                 - (string) $license_key       The license key.
			 *                                 - (string) $site_url          Site URL.
			 *                              // SecuPress.
			 *                                 - (string) $sp_free_version   Version of SecuPress Free.
			 *                                 - (string) $sp_pro_version    Version of SecuPress Pro | Version of SecuPress Free required by SecuPress Pro.
			 *                                 - (string) $sp_active_plugins List of active sub-modules.
			 *                              // WordPress.
			 *                                 - (string) $wp_version        Version of WordPress.
			 *                                 - (string) $is_multisite      Tell if it's a multisite: Yes or No.
			 *                                 - (string) $is_ssl            Tell if SSL is used in back and front: Yes or No.
			 *                                 - (string) $server_type       Apache, Nginx, or IIS.
			 *                                 - (string) $wp_active_plugins List of active WordPress plugins.
			 * @param (object) $this        This `SecuPress_Admin_Support` instance.
			 */
			do_action( 'secupress.services.ask_for_support', $summary, $description, $data, $this );
		} elseif ( ! $this->get_summary() ) {
			// The summary is missing.
			secupress_add_settings_error( 'general', 'no_summary', __( 'Could you please give a short summary of your question?', 'secupress' ) );
		} elseif ( ! $this->get_description() ) {
			// The message is missing.
			secupress_add_settings_error( 'general', 'no_description', __( 'Without any description, it will be difficult to bring you help.', 'secupress' ) );
		} else {
			// The message is the default one.
			secupress_add_settings_error( 'general', 'default_description', __( 'I don\'t think this description can be of any help.', 'secupress' ) );
		}
	}


	/**
	 * Format the data so it can be displayed in a message.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (array) An array of readable "data: value".
	 */
	public function get_formatted_data() {
		$data = $this->get_data();
		$data = array_merge( $data, array(
			// SecuPress.
			'sp_free_version' => sprintf( __( 'SecuPress Free Version: %s', 'secupress' ), $data['sp_free_version'] ),
			// WordPress.
			'wp_version'      => sprintf( __( 'WordPress Version: %s', 'secupress' ), $data['wp_version'] ),
			'is_multisite'    => sprintf( __( 'Multisite: %s', 'secupress' ), $data['is_multisite'] ? __( 'Yes', 'secupress' ) : __( 'No', 'secupress' ) ),
			'is_ssl'          => sprintf( __( 'SSL: %s', 'secupress' ), $data['is_ssl'] ? __( 'Yes', 'secupress' ) : __( 'No', 'secupress' ) ),
		) );

		if ( $this->get_support_scanner() ) {
			secupress_require_class( 'scan' );
			secupress_require_class( 'scan', $this->get_support_scanner() );

			$class_name              = 'SecuPress_Scan_' . $this->get_support_scanner();
			$data['support_scanner'] = sprintf( __( 'Scanner: %s', 'secupress' ), strip_tags( $class_name::get_instance()->title ) );
		}

		if ( static::get_server_type() ) {
			$data['server_type'] = sprintf( __( 'Server Type: %s', 'secupress' ), $data['server_type'] );
		}

		if ( ! secupress_can_access_support() ) {
			return $data;
		}

		$data['sp_active_plugins'] = $data['sp_active_plugins'] ? '<br/>- ' . implode( '<br/>- ', $data['sp_active_plugins'] ) : _x( 'None', 'SecuPress sub-modules', 'secupress' );
		$data['wp_active_plugins'] = $data['wp_active_plugins'] ? '<br/>- ' . implode( '<br/>- ', $data['wp_active_plugins'] ) : _x( 'None', 'WordPress plugins', 'secupress' );

		$data = array_merge( array(
			// Support request.
			'support_scanner'   => '',
			// License.
			'license_email'     => sprintf( __( 'License email: %s', 'secupress' ), $data['license_email'] ),
			'license_key'       => sprintf( __( 'License key: %s', 'secupress' ), $data['license_key'] ),
			'site_url'          => sprintf( __( 'Site URL: %s', 'secupress' ), $data['site_url'] ),
			// SecuPress.
			'sp_free_version'   => '',
			'sp_pro_version'    => sprintf( __( 'SecuPress Pro Version: %s', 'secupress' ), $data['sp_pro_version'] ),
			'sp_active_plugins' => sprintf( __( 'Active sub-modules: %s', 'secupress' ), $data['sp_active_plugins'] ),
			// WordPress.
			'wp_version'        => '',
			'is_multisite'      => '',
			'is_ssl'            => '',
			'server_type'       => '',
			'wp_active_plugins' => sprintf( __( 'Active WordPress plugins: %s', 'secupress' ), $data['wp_active_plugins'] ),
		), $data );

		if ( empty( $data['support_scanner'] ) ) {
			unset( $data['support_scanner'] );
		}

		if ( empty( $data['server_type'] ) ) {
			unset( $data['server_type'] );
		}

		return $data;
	}


	/** Private methods ========================================================================= */

	/**
	 * Sanitize and get the summary.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (string)
	 */
	protected function get_summary() {
		if ( isset( $this->summary ) ) {
			return $this->summary;
		}

		$this->summary = trim( html_entity_decode( $this->settings['support_summary'], ENT_QUOTES ) );
		$this->summary = strip_tags( wp_unslash( $this->summary ) );
		$this->summary = preg_replace( "@[\r\n]+@", ' ', $this->summary );

		return $this->summary;
	}


	/**
	 * Sanitize and get the description.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (string)
	 */
	protected function get_description() {
		if ( isset( $this->description ) ) {
			return $this->description;
		}

		$this->description = trim( html_entity_decode( $this->settings['support_description'], ENT_QUOTES ) );
		$this->description = str_replace( "\r\n", "\n", wp_unslash( $this->description, ENT_QUOTES ) );

		return $this->description;
	}


	/**
	 * Tell if the description is filled and different than the default description.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (bool)
	 */
	protected function has_description() {
		return $this->get_description() && $this->get_description() !== static::get_default_description();
	}


	/**
	 * The user didn't checked the checkbox: store the data sent in a transient and add an error message.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 */
	protected function display_checkbox_message() {
		$transient = array();

		if ( $this->get_summary() ) {
			$transient['summary'] = $this->get_summary();
		}

		if ( $this->has_description() ) {
			$transient['description'] = $this->get_description();
		}

		if ( $transient ) {
			// Set a transient that will fill the fields back.
			set_site_transient( 'secupress_support_form', $transient, 300 );
		}

		secupress_add_settings_error( 'general', 'doc_read', __( 'Please check the checkbox first.', 'secupress' ) );
	}


	/**
	 * Get the data related to the license, the site, etc.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (array)
	 */
	protected function get_data() {
		global $wp_version;

		if ( isset( $this->data ) ) {
			return $this->data;
		}

		$this->data = array(
			// SecuPress.
			'sp_free_version' => SECUPRESS_VERSION,
			// WordPress.
			'wp_version'      => $wp_version,
			'is_multisite'    => (int) is_multisite(),
			'is_ssl'          => (int) secupress_is_site_ssl(),
		);

		// Scanner.
		if ( $this->get_support_scanner() ) {
			$this->data['support_scanner'] = $this->get_support_scanner();
		}

		// Server type.
		if ( static::get_server_type() ) {
			$this->data['server_type'] = static::get_server_type();
		}

		if ( ! secupress_can_access_support() ) {
			return $this->data;
		}

		$this->data = array_merge( $this->data, array(
			// License.
			'license_email'     => secupress_get_consumer_email(),
			'license_key'       => secupress_get_consumer_key(),
			'site_url'          => esc_url( user_trailingslashit( home_url(), 'home' ) ),
			// SecuPress.
			'sp_pro_version'    => SECUPRESS_PRO_VERSION,
			'sp_active_plugins' => secupress_get_active_submodules(),
			// WordPress.
			'wp_active_plugins' => static::get_active_plugins(),
		) );

		// Get the name of the active sub-modules.
		if ( $this->data['sp_active_plugins'] ) {
			$modules = array();

			foreach ( $this->data['sp_active_plugins'] as $module => $submodules ) {
				foreach ( $submodules as $submodule ) {
					$submodule_data = secupress_get_module_data( $module, $submodule );

					if ( ! empty( $submodule_data['Name'] ) ) {
						$modules[] = $submodule_data['Name'];
					} else {
						$modules[] = $module . '/' . $submodule;
					}
				}
			}

			$this->data['sp_active_plugins'] = $modules;
		}

		return $this->data;
	}


	/**
	 * Get the scanner.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (string)
	 */
	protected function get_support_scanner() {
		if ( isset( $this->scanner ) ) {
			return $this->scanner;
		}

		if ( '' !== $this->settings['support_scanner'] ) {
			// Remove the scanner from the referer, we don't want it to be used for the redirection.
			if ( ! empty( $_REQUEST['_wp_http_referer'] ) ) {
				$_REQUEST['_wp_http_referer'] = preg_replace( '@&scanner=' . $this->settings['support_scanner'] . '@i', '', $_REQUEST['_wp_http_referer'] );
			} elseif ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
				$_REQUEST['HTTP_REFERER'] = preg_replace( '@&scanner=' . $this->settings['support_scanner'] . '@i', '', $_REQUEST['HTTP_REFERER'] );
			}
		}

		$this->scanner = sanitize_key( $this->settings['support_scanner'] );

		if ( ! $this->scanner ) {
			return ( $this->scanner = '' );
		}

		$scanners = secupress_get_scanners();
		$scanners = call_user_func_array( 'array_merge', $scanners );
		$scanners = array_combine( array_map( 'strtolower', $scanners ), $scanners );

		if ( ! empty( $scanners[ $this->scanner ] ) && file_exists( secupress_class_path( 'scan', $scanners[ $this->scanner ] ) ) ) {
			$this->scanner = $scanners[ $this->scanner ];
		} else {
			$this->scanner = '';
		}

		return $this->scanner;
	}


	/**
	 * Display a message for the free plugin.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 */
	protected function display_free_plugin_message() {
		$message = sprintf(
			/** Translators: %s is "plugin directory". */
			__( 'Oh, you are using SecuPress Free! The support is handled on the %s. Thank you!', 'secupress' ),
			'<a href="https://wordpress.org/support/plugin/secupress" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">' . __( 'plugin directory', 'secupress' ) . '</a>'
		);

		if ( ! $this->has_description() ) {
			secupress_add_settings_error( 'general', 'free_support', $message );
			return;
		}

		// Maybe add the summary.
		if ( $this->get_summary() ) {
			$message .= '</strong><br/>' . __( 'By the way, here is your subject:', 'secupress' ) . '</p>';
			$message .= '<blockquote>' . esc_html( $this->get_summary() ) . '</blockquote>'; // Escaped.
			$message .= '<p>' . __( 'And your message:', 'secupress' ) . '</p>';
		} else {
			$message .= '</strong><br/>' . __( 'By the way, here is your message:', 'secupress' ) . '</p>';
		}

		// Add the description.
		$description  = wptexturize( $this->get_description() );
		$description  = convert_chars( $description );
		$description  = wpautop( $description, false );
		$description  = preg_replace( '@<p\s*>(.*)</p>@', '\1<br/><br/>', $description );
		$description  = wp_kses( $description, static::get_allowed_tags() );
		$description .= '<br/>' . str_repeat( '-', 40 );
		$description .= '<br/>' . implode( '<br/>', $this->get_formatted_data() );

		$message .= '<blockquote>' . $description . '</blockquote>';
		$message .= '<p>' . __( '(you\'re welcome)', 'secupress' ) . '<strong>';

		secupress_add_settings_error( 'general', 'free_support', $message );
	}


	/** Static methods ========================================================================== */

	/**
	 * Get the default description.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (string)
	 */
	protected static function get_default_description() {
		static $def_description;

		if ( isset( $def_description ) ) {
			return $def_description;
		}

		// For comparison, "encode" the default message the same way we did with the description (no need for `wp_unslash()`, it's not a submitted data).
		$def_description = __( 'Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page', 'secupress' ) . "\n\n" .
		                   __( 'Please let us know how we will recognize the issue or can reproduce the issue. What is supposed to happen, and what is actually happening instead?', 'secupress' );
		$def_description = str_replace( "\r\n", "\n", trim( html_entity_decode( $def_description, ENT_QUOTES ) ) );

		return $def_description;
	}


	/**
	 * Get the server type.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (string)
	 */
	protected static function get_server_type() {
		global $is_apache, $is_nginx, $is_iis7;
		static $server_type;

		if ( isset( $server_type ) ) {
			return $server_type;
		}

		$server_type = '';

		if ( $is_apache ) {
			$server_type = 'Apache';
		} elseif ( $is_nginx ) {
			$server_type = 'Nginx';
		} elseif ( $is_iis7 ) {
			$server_type = 'IIS';
		}

		return $server_type;
	}


	/**
	 * Get the allowed HTML tags.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (array)
	 */
	protected static function get_allowed_tags() {
		return array(
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
	}


	/**
	 * Get name & version of all active plugins.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @return (array) An array of active plugins: name and version.
	 */
	protected static function get_active_plugins() {
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
}
