<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Too Many Admins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Too_Many_Admins extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if there are more than three Administrators on this site.', 'secupress' );
		self::$more  = __( 'Accounts with Administrator privileges can perform any kind of action. The less Administrators you have, the lower the risk that any account has been compromised is.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => _n_noop( 'You have only <strong>%d Administrator</strong>, fine.', 'You have only <strong>%d Administrators</strong>, fine.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d Administrator</strong> found on this site.', '<strong>%d Administrators</strong> found on this site.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
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
			$this->add_message( 0, array( $count, $count ) );
		}

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
