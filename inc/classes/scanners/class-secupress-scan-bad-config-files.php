<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Config Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Config_Files extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your installation contains old or backed up <code>wp-config.php</code> files like <code>wp-config.bak</code>, <code>.old</code> etc.', 'secupress' );
		self::$more  = __( 'Some attackers will try to find old and backed up config files to try to steal them, avoid this attack and remove them!', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t have old <code>wp-config</code> files.', 'secupress' ),
			// bad
			200 => _n_noop( 'Your installation shouldn\'t contain this old or backed up config file: %s.', 'Your installation shouldn\'t contain these old or backed up config files: %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$files = array_flip( array_map( 'basename', (array) glob( ABSPATH . '*wp-config*.*' ) ) );

		unset( $files['wp-config.php'], $files['wp-config-sample.php'] );

		if ( $files ) {
			// bad
			$files = self::wrap_in_tag( array_flip( $files ) );
			$this->add_message( 200, array( count( $files ), wp_sprintf_l( '%l', $files ) ) );
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
