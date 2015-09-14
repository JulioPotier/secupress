<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Admin User scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Admin_User extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	protected static $name = 'admin_user';
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if the "admin" account is correctly protected.', 'secupress' );
		self::$more  = __( 'It\'s important to protect the famous "admin" account to avoid simple brute-force attacks on it.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'The "admin" account is correctly protected.', 'secupress' ),
			// bad
			200 => __( 'The <em>admin</em> account role shouldn\'t be an <strong>administrator</strong>.', 'secupress' ),
			201 => __( 'The <em>admin</em> account <code>ID</code> should be greater than <strong>50</strong>.', 'secupress' ),
			202 => __( 'The <em>admin</em> account should exist (with no role) to avoid someone to register it.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$check = username_exists( 'admin' );

		// Should not be administrator.
		if ( isset( $check->ID ) && user_can( $check, 'administrator' ) ) {
			// bad
			$this->add_message( 200 );
		}

		// ID should be > 25 to avoid simple SQLi.
		if ( isset( $check->ID ) && ( $check->ID < 25 ) ) {		//// 25 ici mais 50 dans le message d'erreur.
			// bad
			$this->add_message( 201 );
		}

		// "admin" user should exist to avoid the creation of this user.
		if ( get_option( 'users_can_register' ) && ! isset( $check->ID ) ) {
			// bad
			$this->add_message( 202 );
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
