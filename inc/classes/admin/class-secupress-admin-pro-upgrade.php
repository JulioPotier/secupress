<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


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
	 * Name of the post action used to install the Pro plugin.
	 *
	 * @var (string)
	 */
	const POST_ACTION = 'secupress_maybe_install_pro_version';

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
	protected function _init() {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			parent::_init();
			return;
		}

		if ( ! secupress_has_pro() ) {
			add_action( 'current_screen',                  array( $this, 'maybe_warn_to_install_pro_version' ) );
			add_action( 'admin_post_' . self::POST_ACTION, array( $this, 'maybe_install_pro_version' ) );
		} else {
			add_action( 'secupress.offer_migration.migration_done', array( $this, 'maybe_trigger_activation_hooks' ) );
			add_action( 'admin_head',                               array( $this, 'maybe_congratulate' ) );
			add_action( 'admin_footer',                             array( $this, 'maybe_redirect_to_settings' ), SECUPRESS_INT_MAX );
		}

		parent::_init();
	}


	/** Public methods ========================================================================== */

	/**
	 * If the `$automatic_install` property is set in the plugin information, redirect and install the Pro version.
	 * Otherwise, display a notice to install the Pro version.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_warn_to_install_pro_version() {
		if ( static::is_update_page() ) {
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

		if ( $information && ! empty( $information->automatic_install ) ) {
			// Install the Pro version by redirecting the user to the install URL.
			unset( $information->automatic_install );
			static::set_transient( $information );

			// This one will be used to do a redirection once the Pro plugin is installed.
			secupress_set_site_transient( 'secupress_offer_migration_redirect', 1 );

			wp_safe_redirect( esc_url_raw( static::get_post_install_url() ) );
			die();
		}

		if ( null === $information ) {
			// The information is not valid, cleanup the transient.
			static::delete_transient();
		}

		// Display a notice asking the user to install the Pro version.
		$message = sprintf(
			/** Translators: 1 is a "upgrade" link. */
			__( 'You can now %s to the Pro version.', 'secupress' ),
			'<a href="' . esc_url( static::get_post_install_url() ) . '">' . _x( 'upgrade', 'verb', 'secupress' ) . '</a>'
		);

		static::add_notice( $message, 'updated', false );
	}


	/**
	 * Maybe install the Pro plugin.
	 * If the Pro plugin information is missing, we get fresh data from our server first.
	 * If the Pro plugin is already installed, we delete it.
	 * Once the information is stored, install the Pro version.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_install_pro_version() {
		if ( ! static::current_user_can() ) {
			return;
		}

		if ( empty( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], self::POST_ACTION ) ) {
			secupress_admin_die();
		}

		if ( ! secupress_has_pro_license() ) {
			// If the license is not valid.
			return;
		}

		// Make sure we have the plugin information.
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
					__( 'A problem occurred while retrieving the Pro version information. Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you’ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
					'<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . esc_url( static::get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
				);

				static::add_transient_notice( $message, 'error' );

				wp_safe_redirect( esc_url_raw( wp_get_referer() ) );
				die();
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
				__( 'It seems you already installed the Pro version. An attempt has been made to replace it with a fresh copy but it couldn’t be deleted (which is not normal). Please download the plugin from your %s and proceed as follow in that order: do NOT uninstall the Free plugin or you’ll lose all your settings (but you can deactivate it if you want), install and activate the Pro plugin, the Free plugin magically disappeared.', 'secupress' ),
				'<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . esc_url( static::get_account_url() ) . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
			);

			static::add_transient_notice( $message, 'error' );

			wp_safe_redirect( esc_url_raw( wp_get_referer() ) );
			die();
		}

		/**
		 * OK, we have all we need, `static::add_migration_data()` will do the rest.
		 */
		wp_safe_redirect( esc_url_raw( static::get_install_url() ) );
		die();
	}


	/**
	 * After Free -> Pro migration, trigger activation hooks.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_trigger_activation_hooks() {
		// Store the user ID, it will be used to display the congratulations notice.
		add_user_meta( get_current_user_id(), 'secupress_migration_congrats', 1, true );

		// Trigger activation hooks.
		$plugin       = static::$plugin_basename;
		$network_wide = is_multisite();
		/** This hook is documented in wp-admin/includes/plugin.php. */
		do_action( "activate_{$plugin}", $network_wide );
	}


	/**
	 * Display a warning when the Pro plugin has been installed.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function maybe_congratulate() {
		if ( ! static::current_user_can() ) {
			return;
		}

		$user_id  = get_current_user_id();
		$congrats = get_user_meta( $user_id, 'secupress_migration_congrats', true );

		if ( ! $congrats ) {
			return;
		}

		delete_user_meta( $user_id, 'secupress_migration_congrats' );

		$message = __( 'Congratulations, your Pro version has been installed 🎉.', 'secupress' );
		static::add_notice( $message );
	}


	/**
	 * Once the Pro version is installed and activated, redirect to the settings page, but only if the user just submitted the license key. This is printed right after the "Plugin reactivated successfully.".
	 *
	 * @since 1.3
	 * @see iframe_footer()
	 * @author Grégory Viguier
	 *
	 * @param (string) $hook_suffix The hook name (also known as the hook suffix) used to determine the current screen.
	 */
	public function maybe_redirect_to_settings( $hook_suffix ) {
		if ( ! static::is_update_page( $hook_suffix ) || ! defined( 'IFRAME_REQUEST' ) || ! IFRAME_REQUEST ) {
			return;
		}

		if ( ! isset( $_GET['action'], $_GET['success'], $_GET['plugin'], $_GET['_wpnonce'] ) || isset( $_GET['failure'] ) ) {
			return;
		}

		if ( 'activate-plugin' !== $_GET['action'] || static::$plugin_basename !== $_GET['plugin'] || ! wp_verify_nonce( $_GET['_wpnonce'], 'activate-plugin_' . $_GET['plugin'] ) ) {
			return;
		}

		if ( secupress_get_site_transient( 'secupress_offer_migration_redirect' ) ) {
			secupress_delete_site_transient( 'secupress_offer_migration_redirect' );
			echo '<script type="text/javascript">window.top.location.href = "' . esc_url_raw( secupress_admin_url( 'settings' ) ) . '";</script>';
		}
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
		if ( $information && is_object( $information ) ) {
			$information->secupress_data_type = 'pro';
		}

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
		$information->secupress_data_type = 'pro';

		$information = static::validate_plugin_information( $information, true );
		return $information;
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
