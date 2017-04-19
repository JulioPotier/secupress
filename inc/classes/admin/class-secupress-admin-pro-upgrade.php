<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Pro upgrade class.
 *
 * @package SecuPress
 * @since 1.3
 */
class SecuPress_Admin_Pro_Upgrade extends SecuPress_Admin_Offer_Migration {

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0';

	/**
	 * The reference to the "Singleton" instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init ==================================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected function init() {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( ! secupress_has_pro() ) {
			// Only for the Free version.
			add_action( 'current_screen',  array( $this, 'maybe_warn_license_is_deactivated' ) );
			add_action( 'current_screen',  array( $this, 'maybe_install_pro_version' ) );
		}

		add_action( 'in_admin_header', array( $this, 'maybe_congratulate' ) );
	}


	/** Public methods ========================================================================== */

	/**
	 * If the license is filled but not activated, tell the user.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_warn_license_is_deactivated() {
		global $current_screen, $pagenow;

		if ( 'update.php' === $pagenow || 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $current_screen->base ) {
			return;
		}

		if ( ! static::current_user_can() ) {
			return;
		}

		if ( secupress_has_pro_license() || ! secupress_get_consumer_key() ) {
			// If the license is valid, or the license is empty.
			return;
		}

		// Display a notice telling the user (his|her) license is deactivated.
		$message = sprintf(
			/** Translators: %s is a "the plugin settings page" link. */
			__( 'Your license is inactive, you should take a look at %s.', 'secupress' ),
			'<a href="' . esc_url( static::get_settings_url() ) . '">' . __( 'the plugin settings page', 'secupress' ) . '</a>'
		);

		static::add_notice( $message, 'error', false );
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

		if ( ! static::current_user_can() ) {
			return;
		}

		if ( ! secupress_has_pro_license() ) {
			// If the license is not valid.
			return;
		}

		$information = static::get_transient();

		if ( null === $information ) {
			// The information is not valid, cleanup the transient.
			static::delete_transient();
		}

		/**
		 * If the information is empty (false) or not valid (null), get fresh data.
		 */
		if ( ! $information ) {
			// At this point, the transient doesn't exist.
			$information = $this->get_remote_information();

			if ( ! $information ) {
				$message = sprintf(
					/** Translators: %s is a link to the "SecuPress account". */
					__( 'A problem occurred while retrieving the Pro version information. Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you\'ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
					'<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . esc_url( static::get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
				);

				static::add_notice( $message, 'error' );
				return;
			}

			static::set_transient( $information );
		}

		/**
		 * If the Pro version is already installed (but not activated of course), we delete it, we want to make sure to install a fresh copy.
		 */
		if ( ! static::delete_pro_plugin() ) {
			static::delete_transient();

			$message = sprintf(
				/** Translators: %s is a link to the "SecuPress account". */
				__( 'It seems you already installed the Pro version. An attempt has been made to replace it with a fresh copy but it couldn\'t be deleted (which is not normal). Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you\'ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
				'<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . esc_url( static::get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
			);

			static::add_notice( $message, 'error' );
			return;
		}

		/**
		 * OK, we have all we need, `static::add_migration_data()` will do the rest.
		 */
		if ( ! empty( $information->automatic_install ) ) {
			// Install the Pro version by redirecting the user to the install URL.
			unset( $information->automatic_install );
			static::set_transient( $information );

			wp_safe_redirect( esc_url_raw( static::get_install_url() ) );
			die();
		}

		// Display a notice asking the user to install the Pro version.
		$message = sprintf(
			/** Translators: 1 is a "upgrade" link. */
			__( 'You can now %s to the Pro version.', 'secupress' ),
			'<a href="' . esc_url( static::get_install_url() ) . '">' . _x( 'upgrade', 'verb', 'secupress' ) . '</a>'
		);

		static::add_notice( $message, 'updated', false );
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

		if ( ! static::current_user_can() ) {
			return;
		}

		$transient = static::get_transient();

		/**
		 * If the transient value is null, that means it contains an invalid value, like a value from the Pro plugin, that is now considered invalid by the Free plugin.
		 * In that case we need to delete it before bailing out.
		 */
		if ( false === $transient ) {
			return;
		}

		// The same transient is used for both migrations, so we delete it in both cases.
		static::delete_transient();

		if ( ! $transient || ! secupress_is_pro() ) {
			// Pro is not activated or the license is not valid.
			return;
		}

		// Add a congratulations notice.
		$message = __( 'Congratulations, your Pro version has been installed 🎉.', 'secupress' );

		static::add_transient_notice( $message );
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
		$information = static::validate_plugin_information( $information, true );

		if ( $information ) {
			static::set_transient( $information, true );
		} else {
			static::delete_transient();
		}
	}


	/** Private methods ========================================================================= */

	/**
	 * Get the Pro plugin information with a remote request.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (object|bool|null) The information object on success, null on failure, false if the data is false.
	 */
	protected function get_remote_information() {
		$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
			'sp_action'  => 'get_upgrade_data',
			'user_email' => secupress_get_consumer_email(),
			'user_key'   => secupress_get_consumer_key(),
			'beta'       => (int) SECUPRESS_USE_BETA,
		) );

		$information = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $information ) || 200 !== wp_remote_retrieve_response_code( $information ) ) {
			return false;
		}

		$information = wp_remote_retrieve_body( $information );
		$information = @json_decode( $information );

		if ( ! is_object( $information ) || empty( $information->success ) ) {
			return null;
		}

		if ( empty( $information->data ) ) {
			return null;
		}

		if ( ! is_array( $information->data ) && ! is_object( $information->data ) ) {
			return null;
		}

		$information = (object) $information->data;

		return static::validate_plugin_information( $information, true );
	}


	/**
	 * Small validation of the data containing the information about the Pro version of the plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object|bool) $information The object containing the information.
	 * @param (bool)        $is_raw_data When true, that means the data comes from a remote request. Some extra validation and formatting are done.
	 *
	 * @return (object|bool|null) The information object on success, null on failure, false if the data is false.
	 */
	protected static function validate_plugin_information( $information, $is_raw_data = false ) {
		$information = parent::validate_plugin_information( $information, $is_raw_data );

		if ( ! $information ) {
			return $information;
		}

		// Make sure the URLs lead to our site.
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
}
