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
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if the <em>admin</em> account is correctly protected.', 'secupress' );
		self::$more  = __( 'It is important to protect the famous <em>admin</em> account to avoid simple brute-force attacks on it. This account is most of the time the first one created when you install WordPress, and it is well known by attackers.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'The <em>admin</em> account is correctly protected.', 'secupress' ),
			// bad
			200 => __( 'The <em>admin</em> account role should not be <strong>Administrator</strong> but should have no role at all.', 'secupress' ),
			201 => __( 'Because the user registration is open, the <em>admin</em> account should exist (with no role) to avoid someone to register it.', 'secupress' ),
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
		if ( false !== $check && user_can( $check, 'administrator' ) ) {
			// bad
			$this->add_message( 200 );
		}

		// // "admin" user should exist to avoid the creation of this user.
		if ( get_option( 'users_can_register' ) && false === $check ) {
			// bad
			$this->add_message( 201 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		$check = username_exists( 'admin' );

		// Should not be administrator.
		if ( false !== $check && user_can( $check, 'administrator' ) ) {
			if ( $check != $current_user->ID ) {
				$user = new WP_User( $check );
				$user->remove_role( 'administrator' );
			} else {
				//// (sweetalert)
			}
		}

		// "admin" user should exist to avoid the creation of this user.
		if ( false === $check && get_option( 'users_can_register' ) ) {
			wp_insert_user( array( 'user_login' => 'admin',
				'user_pass'  => wp_generate_password( 64, 1, 1 ),
				'user_email' => 'secupress_no_mail@fakemail.' . time(),
				'role'       => '', )
			);
		}

		return parent::fix();
	}
}
