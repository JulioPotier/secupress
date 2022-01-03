<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Plugins Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Plugins_Update extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.2';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Tells if the fix must occur after all other scans and fixes, while no other scan/fix is running.
	 *
	 * @var (bool)
	 */
	protected $delayed_fix = true;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your plugins are up to date.', 'secupress' );
		$this->more     = __( 'It is very important to keep your WordPress installation up to date. If you cannot update because of a plugin, contact its author and submit your issue.', 'secupress' );
		$this->more_fix = __( 'Update all your plugins that are not up to date.', 'secupress' );
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'Your plugins are up to date.', 'secupress' ),
			// "warning"
			100 => _n_noop( '<strong>%d symlinked plugin</strong> is not up to date, and cannot be updated automatically.', '<strong>%d symlinked plugins</strong> are not up to date, and cannot be updated automatically.', 'secupress' ),
			// "bad"
			200 => _n_noop( '<strong>%1$d plugin</strong> is not up to date: %2$s.', '<strong>%1$d plugins</strong> are not up to date: %2$s.', 'secupress' ),
			// "cantfix"
			300 => __( 'Some plugins could not be updated correctly.', 'secupress' ),
			301 => _n_noop( '<strong>%d symlinked plugin</strong> is not up to date, and cannot be updated automatically.', '<strong>%d symlinked plugins</strong> are not up to date, and cannot be updated automatically.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/120-plugin-update-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		ob_start();

		wp_update_plugins();
		$plugins           = get_site_transient( 'update_plugins' );
		$plugins           = ! empty( $plugins->response ) && is_array( $plugins->response ) ? array_keys( $plugins->response ) : array();
		$symlinked_plugins = array();

		if ( $plugins ) {
			$symlinked_plugins = array_filter( $plugins, 'secupress_is_plugin_symlinked' );
			$plugins           = array_diff( $plugins, $symlinked_plugins );
			$plugins           = array_flip( $plugins );
			$plugins           = array_intersect_key( get_plugins(), $plugins );
			$plugins           = wp_list_pluck( $plugins, 'Name' );
		}

		ob_flush();

		if ( $count = count( $plugins ) ) {
			// "bad"
			$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $plugins ) ) );
		}

		if ( $count = count( $symlinked_plugins ) ) {
			// "warning"
			$this->add_message( 100, array( $count, $count ) );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( $this->has_fix_action_part( 'fix' ) ) {
			$this->fix();
		}
		// "good"
		$this->add_fix_message( 1 );
		return parent::manual_fix();
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		// Plugins.
		$plugins = get_site_transient( 'update_plugins' );
		$plugins = ! empty( $plugins->response ) && is_array( $plugins->response ) ? array_keys( $plugins->response ) : array();

		if ( $plugins ) {
			$symlinked_plugins = array_filter( $plugins, 'secupress_is_plugin_symlinked' );
			$plugins           = array_diff( $plugins, $symlinked_plugins );
		}

		if ( $plugins ) {
			ob_start();
			secupress_time_limit( 0 );

			// Remove the WP upgrade process for translation since it will output data, use our own based on core but using a silent upgrade.
			remove_action( 'upgrader_process_complete', array( 'Language_Pack_Upgrader', 'async_upgrade' ), 20 );
			add_action( 'upgrader_process_complete', 'secupress_async_upgrades', 20 );

			include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );

			$nonce    = 'bulk-update-plugins';
			$url      = implode( ',', $plugins );
			$url      = 'update.php?action=update-selected&amp;plugins=' . urlencode( $url );
			$skin     = new Automatic_Upgrader_Skin( array( 'nonce' => $nonce, 'url' => $url ) );
			$upgrader = new Plugin_Upgrader( $skin );

			$upgrader->bulk_upgrade( $plugins );

			ob_end_clean();
		}

		// Test if we succeeded.
		$plugins = get_site_transient( 'update_plugins' );
		$plugins = ! empty( $plugins->response ) && is_array( $plugins->response ) ? array_keys( $plugins->response ) : array();

		if ( ! $plugins ) {
			// "good"
			$this->add_fix_message( 0 );
		} else {
			$symlinked_plugins = array_filter( $plugins, 'secupress_is_plugin_symlinked' );
			$plugins           = array_diff( $plugins, $symlinked_plugins );

			if ( $count = count( $symlinked_plugins ) ) {
				// "cantfix"
				$this->add_fix_message( 301, array( $count, $count ) );
			} else {
				// "cantfix"
				$this->add_fix_message( 300 );
			}
		}

		return parent::fix();
	}
}
