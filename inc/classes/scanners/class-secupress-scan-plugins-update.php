<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Plugins Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Plugins_Update extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio        = 'high';
	public    static $delayed_fix = true;


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your plugins are up to date.', 'secupress' );
		self::$more     = __( 'It is very important to maintain your WordPress installation up to date. If you can not update because of a plugin, contact its author and submit your issue.', 'secupress' );
		self::$more_fix = __( 'This will update all your plugins that are not up to date.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your plugins are up to date.', 'secupress' ),
			// warning
			100 => _n_noop( '<strong>%d symlinked plugin</strong> is not up to date, and I cannot update it automatically.', '<strong>%d symlinked plugins</strong> are not up to date, and I cannot update them automatically.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%1$d plugin</strong> is not up to date: %2$s.', '<strong>%1$d plugins</strong> are not up to date: %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'Some plugins could not be updated correctly.', 'secupress' ),
			301 => _n_noop( '<strong>%d symlinked plugin</strong> is not up to date, and I cannot update it automatically.', '<strong>%d symlinked plugins</strong> are not up to date, and I cannot update them automatically.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
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
			// bad
			$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $plugins ) ) );
		}

		if ( $count = count( $symlinked_plugins ) ) {
			// warning
			$this->add_message( 100, array( $count, $count ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		// Plugins
		$plugins = get_site_transient( 'update_plugins' );
		$plugins = ! empty( $plugins->response ) && is_array( $plugins->response ) ? array_keys( $plugins->response ) : array();

		if ( $plugins ) {
			$symlinked_plugins = array_filter( $plugins, 'secupress_is_plugin_symlinked' );
			$plugins           = array_diff( $plugins, $symlinked_plugins );
		}

		if ( $plugins ) {
			ob_start();
			@set_time_limit( 0 );

			// remove the WP upgrade process for translation since it will output data, use our own based on core but using a silent upgrade.
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
			// good
			$this->add_fix_message( 0 );
		} else {
			$symlinked_plugins = array_filter( $plugins, 'secupress_is_plugin_symlinked' );
			$plugins           = array_diff( $plugins, $symlinked_plugins );

			if ( $count = count( $symlinked_plugins ) ) {
				// cantfix
				$this->add_fix_message( 301, array( $count, $count ) );
			} else {
				// cantfix
				$this->add_fix_message( 300 );
			}
		}

		return parent::fix();
	}
}
