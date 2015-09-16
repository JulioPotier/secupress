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
			200 => __( 'Your installation <strong>can NOT auto-update</strong> itself.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
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
			$this->add_message( 200 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
