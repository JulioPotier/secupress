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
	public    static $prio = 'high';


	protected static function init() {
		self::$type    = 'WordPress';
		self::$title   = __( 'Check if your plugins are up to date.', 'secupress' );
		self::$more    = __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin, contact its author and submit your issue.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your plugins are up to date.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%1$d plugin</strong> isn\'t up to date: %2$s.', '<strong>%1$d plugins</strong> aren\'t up to date: %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'Some plugins could not be updated correctly.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		ob_start();

		// Plugins
		wp_update_plugins();
		$current        = get_site_transient( 'update_plugins' );
		$plugin_updates = array();

		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$plugin_updates = wp_list_pluck( array_intersect_key( get_plugins(), array_flip( array_keys( $current->response ) ) ), 'Name' );
		}

		ob_flush();

		if ( $count = count( $plugin_updates ) ) {
			// bad
			$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $plugin_updates ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		ob_start();
		@set_time_limit( 0 );

		// Plugins
		$plugins = get_site_transient( 'update_plugins' );
		$plugins = isset( $plugins->response ) ? array_keys( $plugins->response ) : false;
		if ( $plugins ) {
			// remove the WP upgrade process for translation since it will output data, use our own based on core but using a silent upgrade
			remove_action( 'upgrader_process_complete', array( 'Language_Pack_Upgrader', 'async_upgrade' ), 20 );
			add_action( 'upgrader_process_complete', 'secupress_async_upgrades', 20 );

			$url = 'update.php?action=update-selected&amp;plugins=' . urlencode( implode( ',', $plugins ) );
			$nonce = 'bulk-update-plugins';
			include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
			$skin = new Automatic_Upgrader_Skin( compact( 'nonce', 'url' ) );
			$upgrader = new Plugin_Upgrader( $skin );
			$upgrader->bulk_upgrade( $plugins );
		}

		ob_end_clean();

		$plugins = get_site_transient( 'update_plugins' );
		$plugins = isset( $plugins->response ) ? array_keys( $plugins->response ) : false;
		if ( ! $plugins ) {
			$this->add_fix_message( 0 );
		} else {
			$this->add_fix_message( 300 );
		}

		return parent::fix();
	}
}
