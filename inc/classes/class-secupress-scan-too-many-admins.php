<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Too Many Admins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Too_Many_Admins extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'too_many_admins';
	public    static $prio = 'medium';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if there is more than 3 administrators on this site.', 'secupress' );
		self::$more  = __( 'Try to reduce the number of administrators to lower the risk that any account has been compromised.', 'secupress' );
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'You have 3 or less administrator, fine.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d administrator</strong> found on this site.', '<strong>%d administrators</strong> found on this site.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$count = count( get_users( array(
			'fields' => 'ids',
			'role' => 'administrator',
		) ) );

		if ( $count > 3 ) {
			// bad
			$this->add_message( 200, array( $count, $count ) );
		} else {
			// good
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
