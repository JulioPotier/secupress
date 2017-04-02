<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Pro upgrade class.
 *
 * @package SecuPress
 * @since 1.3
 */
class SecuPress_Admin_Pro_Upgrade extends SecuPress_Singleton {

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0';

	/**
	 * Name of the transient used to store the Pro plugin information.
	 *
	 * @var (string)
	 */
	const TRANSIENT_NAME = 'secupress_pro_information';

	/**
	 * The reference to the "Singleton" instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init ==================================================================================== */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected function _init() {
		add_filter( 'secupress.options.load_plugins_network_options', array( $this, 'autoload_transient' ) );
		add_filter( 'site_transient_update_plugins', array( $this, 'upgrade_to_pro' ) );

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		add_action( 'current_screen',  array( $this, 'maybe_install_pro_version' ) );
		add_action( 'current_screen',  array( $this, 'maybe_warn_no_license' ) );
		add_action( 'in_admin_header', array( $this, 'maybe_congratulate' ) );
	}


	/** Public methods ========================================================================== */

	/**
	 * Add our transient to the list of network options to autoload.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (array) $option_names An array of network option names.
	 *
	 * @return (array)
	 */
	public function autoload_transient( $option_names ) {
		$option_names[] = '_site_transient_' . self::TRANSIENT_NAME;
		return $option_names;
	}


	/**
	 * Filter the value of the 'update_plugins' site transient to upgrade from Free to Pro.
	 * We add a "fake" update to the Free plugin, containing the Pro information.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object|bool) $value Value of the site transient: an object or false.
	 *
	 * @return (object|bool)
	 */
	public function upgrade_to_pro( $value ) {
		global $pagenow;

		if ( secupress_has_pro() ) {
			// If it's the pro version.
			return;
		}

		$plugin = plugin_basename( SECUPRESS_FILE );

		if ( 'update.php' !== $pagenow || ! is_object( $value ) ) {
			return $value;
		}

		if ( ! isset( $_GET['action'], $_GET['plugin'] ) || 'upgrade-plugin' !== $_GET['action'] || $plugin !== $_GET['plugin'] ) {
			// Only when requesting the update.
			return $value;
		}

		$pro_information = $this->get_transient();

		if ( null === $pro_information ) {
			// The information is not valid, cleanup the transient.
			$this->delete_transient();
			return $value;
		}

		if ( ! $pro_information ) {
			// The transient doesn't exist.
			return $value;
		}

		// Add the data to the transient.
		unset( $value->no_update[ $plugin ] );

		if ( ! isset( $value->response ) || ! is_array( $value->response ) ) {
			$value->response = array();
		}

		$value->response[ $plugin ] = $pro_information;

		return $value;
	}


	/**
	 * Maybe install the Pro plugin.
	 * If the Pro plugin information is missing, we get fresh data from our server first.
	 * Once the information is stored, display a notice to install the Pro version.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_install_pro_version() {
		global $pagenow;

		if ( 'update.php' === $pagenow ) {
			// This is the page where WP displays when installing a plugin.
			return;
		}

		if ( ! $this->current_user_can() ) {
			return;
		}

		if ( secupress_has_pro() || ! secupress_has_pro_license() ) {
			// If it's the pro version, or if the license is not valid.
			return;
		}

		$pro_information = $this->get_transient();

		if ( null === $pro_information ) {
			// The information is not valid, cleanup the transient.
			$this->delete_transient();
		}

		/**
		 * If the information is empty (false) or not valid (null), get fresh data.
		 */
		if ( ! $pro_information ) {
			// At this point, the transient doesn't exist.
			$pro_information = $this->get_remote_information();

			if ( ! $pro_information ) {
				$message = sprintf(
					/** Translators: %s is a link to the "SecuPress account". */
					__( 'A problem occurred while retrieving the Pro version information. Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you\'ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
					'<a target="_blank" href="' . esc_url( $this->get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
				);

				$this->add_notice( $message, 'error', '' );
				return;
			}

			$this->set_transient( $pro_information );
		}

		/**
		 * If the Pro version is already installed (but not activated of course), we delete it, we want to make sure to install a fresh copy.
		 */
		if ( ! $this->delete_pro_plugin() ) {
			$this->delete_transient();

			$message = sprintf(
				/** Translators: %s is a link to the "SecuPress account". */
				__( 'It seems you already installed the Pro version. An attempt has been made to replace it with a fresh copy but it couldn\'t be deleted (which is not normal). Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you\'ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
				'<a target="_blank" href="' . esc_url( $this->get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
			);

			$this->add_notice( $message, 'error', '' );
			return;
		}

		/**
		 * OK, we have all we need, `$this->upgrade_to_pro()` will do the rest.
		 */
		if ( ! empty( $pro_information->automatic_install ) ) {
			// Install the Pro version by redirecting the user to the install URL.
			unset( $pro_information->automatic_install );
			$this->set_transient( $pro_information );

			wp_safe_redirect( esc_url_raw( $this->get_install_url() ) );
			die();
		}

		// Display a notice asking the user to install the Pro version.
		$message = sprintf(
			/** Translators: 1 is a "upgrade" link. */
			__( 'you can now %s to the Pro version.', 'secupress' ),
			'<a href="' . esc_url( $this->get_install_url() ) . '">' . __( 'upgrade', 'secupress' ) . '</a>'
		);

		$this->add_notice( $message, 'updated', false );
	}


	/**
	 * Display a warning when the license is not valid.
	 *
	 * @since 1.3
	 * @see Was previously `secupress_warning_no_license()`.
	 * @author Grégory Viguier
	 */
	public function maybe_warn_no_license() {
		global $current_screen;

		if ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $current_screen->base ) {
			return;
		}

		if ( ! $this->current_user_can() ) {
			return;
		}

		if ( ! secupress_has_pro() || secupress_is_pro() ) {
			// Pro is not activated, or Pro is activated and the license is valid.
			return;
		}

		$message = sprintf(
			/** Translators: %s is a link to the "plugin settings page". */
			__( 'Your Pro license is not valid or is not set yet. If you want to activate all the Pro features, premium support and updates, take a look at %s.', 'secupress' ),
			'<a href="' . esc_url( secupress_admin_url( 'settings' ) ) . '">' . __( 'the plugin settings page', 'secupress' ) . '</a>'
		);

		$this->add_notice( $message, 'updated', false );
	}


	/**
	 * Display a warning when the Pro plugin has been installed (once).
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_congratulate() {
		global $pagenow;

		if ( 'update.php' === $pagenow ) {
			return;
		}

		if ( ! $this->current_user_can() ) {
			return;
		}

		if ( ! secupress_is_pro() ) {
			// Pro is not activated or the license is not valid.
			return;
		}

		if ( ! $this->get_transient() ) {
			return;
		}

		$this->delete_transient();

		// Add a congratulations notice.
		$message = __( 'congratulations, your Pro version has been installed.', 'secupress' );

		$this->add_transient_notice( $message, 'updated', '' );
	}


	/**
	 * Get our (validated) transient.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (object|bool) The Pro plugin information. False if empty.
	 */
	public function get_transient() {
		$information = secupress_get_site_transient( self::TRANSIENT_NAME );
		return $this->validate_plugin_information( $information );
	}


	/**
	 * Delete our transient.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function delete_transient() {
		secupress_delete_site_transient( self::TRANSIENT_NAME );
	}


	/**
	 * Set our transient.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object) $information       The Pro plugin information.
	 * @param (bool)   $automatic_install When true, the property `automatic_install` is added to the transient value.
	 *                                    This property is used in `$this->maybe_install_pro_version()` to automatically redirect the user to the installation process.
	 */
	public function set_transient( $information, $automatic_install = false ) {
		if ( $automatic_install ) {
			$information->automatic_install = 1;
		}

		secupress_set_site_transient( self::TRANSIENT_NAME, $information );
	}


	/**
	 * Validate raw data for our transient and, depending on the result, delete the transient or set its value.
	 * If the transient is set, the `$automatic_install` is set to true.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object|bool) $information The Pro plugin information. False otherwise.
	 */
	public function maybe_set_transient_from_remote( $information ) {
		$information = $this->validate_plugin_information( $information, true );

		if ( $information ) {
			$this->set_transient( $information, true );
		} else {
			$this->delete_transient();
		}
	}


	/**
	 * Small validation of the data containing the information about the Pro version of the plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object|bool) $information The object containing the information.
	 * @param (bool)        $raw_data    When true, that means the data comes from a remote request. Some extra validation and formatting are done.
	 *
	 * @return (object|bool|null) The information object on success, null on failure, false if the data is false.
	 */
	public function validate_plugin_information( $information, $raw_data = false ) {
		if ( false === $information ) {
			return false;
		}

		// Make sure tha data is what we expect.
		if ( ! $information || ! is_object( $information ) ) {
			return null;
		}

		if ( $raw_data ) {
			// Extra cleanse.
			if ( ! isset( $information->sections ) ) {
				return null;
			}

			$information->sections = maybe_unserialize( $information->sections );

			if ( isset( $information->banners ) ) {
				$information->banners = maybe_unserialize( $information->banners );
			}

			if ( ! empty( $information->sections ) ) {
				foreach ( $information->sections as $key => $section ) {
					$information->$key = (array) $section;
				}
				unset( $information->sections );
			}
		}

		// Make sure the stored URLs leads to our site.
		$secupress_url = trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) );
		$url_keys      = array( 'url', 'homepage', 'package', 'download_link' );

		foreach ( $url_keys as $url_key ) {
			if ( empty( $information->$url_key ) ) {
				continue;
			}

			$url_key = set_url_scheme( $information->$url_key, 'https' );

			if ( strpos( $url_key, $secupress_url ) !== 0 ) {
				return null;
			}
		}

		return $information;
	}


	/** Private methods ========================================================================= */

	/**
	 * Tell if the current user has the capability to manipulate SecuPress.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (bool)
	 */
	protected function current_user_can() {
		static $can;

		if ( ! isset( $can ) ) {
			$can = current_user_can( secupress_get_capability() );
		}

		return $can;
	}


	/**
	 * Get the Pro plugin information with a remote request.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (object|bool|null) The information object on success, null on failure, false if the data is false.
	 */
	protected function get_remote_information() {
		$pro_information = wp_remote_post( SECUPRESS_WEB_MAIN, array(
			'timeout'   => 15,
			'sslverify' => false,
			'body'      => array(
				'edd_action' => 'get_version',
				'license'    => secupress_get_consumer_key(),
				'item_name'  => 'SecuPress',
				'slug'       => 'secupress-pro',
				'author'     => 'WP Media',
				'url'        => home_url(),
			),
		) );

		if ( ! is_wp_error( $pro_information ) ) {
			$pro_information = json_decode( wp_remote_retrieve_body( $pro_information ) );
		} else {
			$pro_information = false;
		}

		return $this->validate_plugin_information( $pro_information, true );
	}


	/**
	 * Delete the Pro plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (bool) True on success or if the plugin wasn't installed. False on failure.
	 */
	protected function delete_pro_plugin() {
		$filesystem = secupress_get_filesystem();

		if ( secupress_has_pro() ) {
			$path = SECUPRESS_FILE;
		} else {
			$path = dirname( dirname( SECUPRESS_FILE ) ) . '/secupress-pro/secupress-pro.php';
		}

		if ( ! $filesystem->exists( $path ) ) {
			return true;
		}

		return $filesystem->delete( dirname( $path ), true );
	}


	/**
	 * Get the URL of the user account on secupress.me.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	protected function get_account_url() {
		/** Translators: this is the slug (part of the URL) of the account page on secupress.me, like in https://secupress.me/account/, it must not be translated if the page doesn't exist. */
		return SECUPRESS_WEB_MAIN . _x( 'account', 'URL slug', 'secupress' ) . '/';
	}


	/**
	 * Get the URL allowing to install the Pro plugin.
	 * While we want to install the Pro plugin, it's the URL for the Free plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	protected function get_install_url() {
		$plugin      = plugin_basename( SECUPRESS_FILE );
		$install_url = array(
			'action'   => 'upgrade-plugin',
			'plugin'   => $plugin,
			'_wpnonce' => wp_create_nonce( 'upgrade-plugin_' . $plugin ),
		);

		return add_query_arg( $install_url, self_admin_url( 'update.php' ) );
	}


	/**
	 * Add an admin notice.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string)      $message    The message to display in the notice.
	 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
	 * @param (string|bool) $notice_id  A unique identifier to tell id the notice is dismissible.
	 *                                  false: the notice is not dismissible.
	 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
	 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
	 */
	protected function add_notice( $message, $error_code = 'updated', $notice_id = '' ) {
		$message = sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ' . $message;

		secupress_add_notice( $message, $error_code, $notice_id );
	}


	/**
	 * Add a "transient" admin notice.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string)      $message    The message to display in the notice.
	 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
	 * @param (string|bool) $notice_id  A unique identifier to tell id the notice is dismissible.
	 *                                  false: the notice is not dismissible.
	 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
	 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
	 */
	protected function add_transient_notice( $message, $error_code = 'updated', $notice_id = '' ) {
		$message = sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ' . $message;

		secupress_add_transient_notice( $message, $error_code, $notice_id );
	}
}
