<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Login Errors Disclose scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Login_Errors_Disclose extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'login_errors_disclose';
	public    static $prio = 'low';


	public function __construct() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses some login errors.', 'secupress' );
		self::$more  = __( 'Don\'t let them easily find these informations.', 'secupress' ); ////
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently not displaying <strong>Login errors</strong>.', 'secupress' ),
			// bad
			200 => __( '<strong>Login errors</strong> shouldn\'t be displayed.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$check = apply_filters( 'login_errors', 'errors' );

		if ( 'errors' === $check ) {
			// bad
			$this->add_message( 200 );
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
