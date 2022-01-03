<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Free / Pro migration class. This class must be extended.
 *
 * @package SecuPress
 * @since 1.3
 */
abstract class SecuPress_Admin_Offer_Migration extends SecuPress_Singleton {

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
	const TRANSIENT_NAME = 'secupress_offer_migration_information';

	/**
	 * Plugin basename of the Free plugin.
	 *
	 * @var (string)
	 */
	protected static $free_plugin_basename;

	/**
	 * Plugin basename of the Pro plugin.
	 *
	 * @var (string)
	 */
	protected static $pro_plugin_basename;

	/**
	 * Plugin basename of the current plugin.
	 *
	 * @var (string)
	 */
	protected static $plugin_basename;

	/**
	 * Path to the Free plugin.
	 *
	 * @var (string)
	 */
	protected static $free_plugin_path;

	/**
	 * Path to the Pro plugin.
	 *
	 * @var (string)
	 */
	protected static $pro_plugin_path;

	/**
	 * Tell if the init has been done.
	 *
	 * @var (bool)
	 */
	private static $init_done = false;


	/** Init ==================================================================================== */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected function _init() {
		if ( self::$init_done ) {
			return;
		}
		self::$init_done = true;

		if ( ! secupress_has_pro() ) {
			// This is the Free plugin.
			static::$free_plugin_basename = plugin_basename( SECUPRESS_FILE );
			static::$pro_plugin_basename  = 'secupress-pro/secupress-pro.php';
			static::$plugin_basename      = static::$free_plugin_basename;

			static::$free_plugin_path     = SECUPRESS_FILE;
			static::$pro_plugin_path      = dirname( dirname( SECUPRESS_FILE ) ) . '/' . static::$pro_plugin_basename;
		} else {
			// This is the Pro plugin.
			static::$free_plugin_basename = 'secupress/secupress.php';
			static::$pro_plugin_basename  = plugin_basename( SECUPRESS_FILE );
			static::$plugin_basename      = static::$pro_plugin_basename;

			static::$free_plugin_path     = dirname( dirname( SECUPRESS_FILE ) ) . '/' . static::$free_plugin_basename;
			static::$pro_plugin_path      = SECUPRESS_FILE;
		}

		add_filter( 'site_transient_update_plugins', array( __CLASS__, 'maybe_add_migration_data' ) );

		static::maybe_end_migration();
	}


	/** Public methods ========================================================================== */

	/**
	 * Filter the value of the 'update_plugins' site transient to upgrade from Free to Pro, or Pro to Free.
	 * We add a "fake" update to the Free/Pro plugin, containing the Pro/Free information.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object|bool) $value Value of the site transient: an object or false.
	 *
	 * @return (object|bool)
	 */
	public static function maybe_add_migration_data( $value ) {
		$plugin = static::$plugin_basename;

		if ( ! static::is_update_page() || ! is_object( $value ) ) {
			return $value;
		}

		if ( ! isset( $_GET['action'], $_GET['plugin'] ) || 'upgrade-plugin' !== $_GET['action'] || $plugin !== $_GET['plugin'] ) {
			// Only when requesting the update.
			return $value;
		}

		$information = static::get_transient();

		if ( null === $information ) {
			// The information is not valid, cleanup the transient.
			static::delete_transient();
			return $value;
		}

		if ( ! $information ) {
			// The transient doesn't exist.
			return $value;
		}

		// Add the data to the transient.
		unset( $value->no_update[ $plugin ] );

		if ( ! isset( $value->response ) || ! is_array( $value->response ) ) {
			$value->response = array();
		}

		$value->response[ $plugin ] = $information;

		add_filter( 'upgrader_post_install',     array( __CLASS__, 'prevent_js_error' ), SECUPRESS_INT_MAX );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'cleanup_license' ), 100, 2 );

		return $value;
	}


	/**
	 * Prevent a stupid JS error.
	 *
	 * @since 1.3
	 * @see WP_Upgrader_Skin::decrement_update_count()
	 * @author Grégory Viguier
	 *
	 * @param (bool|object) $response Install response.
	 *
	 * @return (bool|object)
	 */
	public static function prevent_js_error( $response ) {
		if ( ! $response || is_wp_error( $response ) || 'up_to_date' === $response ) {
			return $response;
		}

		echo '<script type="text/javascript">
				window.wp = window.wp || {};
				window.wp.updates = window.wp.updates || {};
			</script>';

		return $response;
	}


	/**
	 * Once the migration process is complete: remove the license from the Free, or remove any license error from the Pro.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (object) $upgrader   WP_Upgrader instance. In other contexts, $this, might be a Theme_Upgrader, Plugin_Upgrader, Core_Upgrade, or Language_Pack_Upgrader instance.
	 * @param (array)  $hook_extra Array of bulk item update data.
	 */
	public static function cleanup_license( $upgrader, $hook_extra ) {
		if ( empty( $hook_extra['plugin'] ) || empty( $upgrader->result ) || is_wp_error( $upgrader->result ) ) {
			return;
		}

		$options = get_site_option( SECUPRESS_SETTINGS_SLUG );

		// Both versions: remove any license error.
		unset( $options['license_error'] );

		if ( $hook_extra['plugin'] === static::$pro_plugin_basename ) {
			// Free plugin: remove the license and license error.
			unset( $options['consumer_email'], $options['consumer_key'], $options['site_is_pro'] );
		}

		secupress_update_options( $options );

		/**
		 * Tell the migration is done.
		 *
		 * We can't trigger the new plugin activation hook now because in case of Free -> Pro migration, the Pro plugin is not included yet, it will be at next page load. So instead we store the information.
		 * See `static::maybe_end_migration()`.
		 */
		$transient = static::get_transient();
		$transient->migration_done = 1;
		static::set_transient( $transient );
	}


	/**
	 * Delete the migration data and trigger a "migration done" action.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public static function maybe_end_migration() {
		if ( static::is_update_page() ) {
			return;
		}

		$transient = static::get_transient( true );

		if ( empty( $transient->migration_done ) ) {
			return;
		}

		$type = ! empty( $transient->secupress_data_type ) ? $transient->secupress_data_type : false;

		if ( ! $type || ( secupress_has_pro() && 'free' === $type ) || ( ! secupress_has_pro() && 'pro' === $type ) ) {
			return;
		}

		/**
		 * Triggers after the offer migration.
		 *
		 * @since 1.3
		 * @author Grégory Viguier
		 */
		do_action( 'secupress.offer_migration.migration_done' );

		static::delete_transient();
	}


	/**
	 * Get the URL of the user account on secupress.me.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	public static function get_account_url() {
		/** Translators: this is the slug (part of the URL) of the account page on secupress.me, like in https://secupress.me/account/, it must not be translated if the page doesn't exist. */
		return SECUPRESS_WEB_MAIN . _x( 'account', 'URL slug', 'secupress' ) . '/';
	}


	/**
	 * Get the URL of our support page on secupress.me.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	public static function get_support_url() {
		$email = 'sserpuces' . chr( 64 );
		$email = strrev( 'em.' . $email . 'troppus' );

		$subject = esc_html__( 'HALP!', 'secupress' );
		$subject = wp_specialchars_decode( $subject );
		$subject = str_replace( '+', '%20', urlencode( $subject ) );

		return 'mailto:' . $email . '?subject=' . $subject;
	}


	/**
	 * Get the URL allowing to install the Free or Pro plugin.
	 * While we want to install the Pro plugin, it's the URL for the Free plugin. And it's the opposite when we want to install the Free plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	public static function get_install_url() {
		$install_url = is_multisite() ? network_admin_url( 'update.php' ) : admin_url( 'update.php' );
		$args        = array(
			'action'   => 'upgrade-plugin',
			'plugin'   => static::$plugin_basename,
			'_wpnonce' => wp_create_nonce( 'upgrade-plugin_' . static::$plugin_basename ),
		);

		return add_query_arg( $args, $install_url );
	}


	/**
	 * Get the URL allowing to install the Free plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	protected static function get_post_install_url() {
		$install_url = admin_url( 'admin-post.php' );
		$args        = array(
			'action'   => static::POST_ACTION,
			'_wpnonce' => wp_create_nonce( static::POST_ACTION ),
		);

		return add_query_arg( $args, $install_url );
	}


	/**
	 * Get the URL of the settings page.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (string) A URL.
	 */
	public static function get_settings_url() {
		return secupress_admin_url( 'settings' );
	}


	/**
	 * Get our (validated) transient.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (bool) $raw True to return raw data. False to validate before returning.
	 *
	 * @return (object|bool) The Pro plugin information. False if empty.
	 */
	public static function get_transient( $raw = false ) {
		$information = secupress_get_site_transient( self::TRANSIENT_NAME );
		return $raw ? $information : static::validate_plugin_information( $information );
	}


	/**
	 * Delete our transient.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public static function delete_transient() {
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
	public static function set_transient( $information, $automatic_install = false ) {
		if ( $automatic_install ) {
			$information->automatic_install = 1;
		}

		secupress_set_site_transient( self::TRANSIENT_NAME, $information );
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
	protected static function current_user_can() {
		static $can;

		if ( ! isset( $can ) ) {
			$can = current_user_can( secupress_get_capability() );
		}

		return $can;
	}


	/**
	 * Tell if we're in the page that WP displays when we're installing a plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $current_page The current screen name.
	 */
	protected static function is_update_page( $current_page = null ) {
		global $pagenow;

		if ( $current_page ) {
			return 'update.php' === $current_page;
		}

		return 'update.php' === $pagenow;
	}


	/**
	 * Tell if we're in our settings page.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	protected static function is_settings_page() {
		global $current_screen;

		$base = SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' . ( is_multisite() ? '-network' : '' );

		return $base === $current_screen->base;
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
		if ( false === $information ) {
			return false;
		}

		// Make sure tha data is what we expect.
		if ( ! $information || ! is_object( $information ) ) {
			return null;
		}

		// Make sure it's the data for the right plugin (in Free we want Pro data, and in Pro we want Free data).
		$is_pro = secupress_has_pro();
		$type   = ! empty( $information->secupress_data_type ) ? $information->secupress_data_type : false;

		if ( ! $type || ( $is_pro && 'free' !== $type ) || ( ! $is_pro && 'pro' !== $type ) ) {
			return null;
		}

		if ( ! $is_raw_data ) {
			return $information;
		}

		// Keep only the needed data and fill in the empty values.
		$information = (array) $information;
		$information = secupress_array_merge_intersect( $information, array(
			'name'                => '', // Should be set.
			'slug'                => '', // Should be set (but useless).
			'plugin'              => '',
			'version'             => '', // Should be set.
			'new_version'         => '',
			'homepage'            => '', // Should be set.
			'url'                 => '',
			'download_link'       => '', // Should be set.
			'package'             => '',
			'secupress_data_type' => '', // Is set.
		) );

		$information['slug']   = dirname( static::$plugin_basename );
		$information['plugin'] = static::$plugin_basename;

		if ( empty( $information['new_version'] ) ) {
			$information['new_version'] = $information['version'];
		}

		if ( empty( $information['url'] ) ) {
			$information['url'] = $information['homepage'];
		}

		if ( empty( $information['package'] ) ) {
			$information['package'] = $information['download_link'];
		}

		return (object) $information;
	}


	/**
	 * Delete the Pro plugin.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @return (bool) True on success or if the plugin wasn't installed. False on failure.
	 */
	protected static function delete_pro_plugin() {
		$filesystem = secupress_get_filesystem();

		if ( ! $filesystem->exists( static::$pro_plugin_path ) ) {
			return true;
		}

		return $filesystem->delete( dirname( static::$pro_plugin_path ), true );
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
	protected static function add_notice( $message, $error_code = 'updated', $notice_id = '' ) {
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
	protected static function add_transient_notice( $message, $error_code = 'updated', $notice_id = '' ) {
		$message = sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ' . $message;

		secupress_add_transient_notice( $message, $error_code, $notice_id );
	}
}
