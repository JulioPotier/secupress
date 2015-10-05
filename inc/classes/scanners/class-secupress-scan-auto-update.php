<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Auto Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Auto_Update extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress core can perform auto-updates for minor versions.', 'secupress' );
		self::$more  = __( 'When a minor update is released, WordPress can install it automatically. By doing so, you are always up to date when a security flaw is discovered.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your installation <strong>can auto-update</strong> itself.', 'secupress' ),
			// bad
			200 => __( 'Your installation <strong>can not auto-update</strong> itself.', 'secupress' ),
			201 => __( '<code>DISALLOW_FILE_MODS</code> should be set on <code>FALSE</code>.', 'secupress' ),
			202 => __( '<code>AUTOMATIC_UPDATER_DISABLED</code> should be set on <code>FALSE</code>.', 'secupress' ),
			203 => __( '<code>DISALLOW_FILE_MODS</code> and <code>AUTOMATIC_UPDATER_DISABLED</code> should be set on <code>FALSE</code>.', 'secupress' ),
			// cantfix
			300 => __( 'The filter <code>automatic_updater_disabled</code> should not be used, we can not overwrite it.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		require_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );

		$updater = new WP_Automatic_Updater();
		$check = (bool) $updater->is_disabled();

		if ( $check ) {
			// bad
			$constants = 0;
			if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
				$constants += 1;
			}

			if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
				$constants += 2;
			}

			if ( $constants ) {
				$this->add_message( 200 );
				$this->add_message( 200 + $constants );
			} else {
				$this->add_message( 0 );
			}
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		$settings = array( 'plugin_minor_updates' => '1' );
		secupress_activate_module( 'wordpress-core', $settings );
		secupress_activate_submodule( 'wordpress-core', 'minor-updates' );

		$this->add_fix_message( 0 );

		return parent::fix();
	}


}
