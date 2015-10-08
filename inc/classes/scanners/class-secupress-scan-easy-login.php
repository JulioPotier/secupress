<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Easy Login scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Easy_Login extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your login page is protected by double authentication or something like that (may be a custom script).', 'secupress' );
		self::$more  = __( 'The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'The login page seems to be protected by double authentication or a custom script.', 'secupress' ),
			1   => __( 'The <strong>Double Authentication</strong> module has been activated with <strong>Mobile Authenticator App</strong> option.', 'secupress' ),
			2   => __( 'The <strong>Double Authentication</strong> module has been activated with <strong>PasswordLess - Email</strong> option. Users will receive an email to log-in now.', 'secupress' ),
			// warning
			100 => __( 'Unable to create a user to test the login authentication system.', 'secupress' ),
			// bad
			200 => __( 'Your login system is <strong>not strong enough</strong>, you need a <strong>double authentication system</strong>.', 'secupress' ),
			201 => __( 'The registration page is <strong>not protected</strong> from bots.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$temp_login = uniqid( 'secupress' );
		$temp_pass  = wp_generate_password( 64 );
		$temp_id    = wp_insert_user( array(
			'user_login' => $temp_login,
			'user_pass'  => $temp_pass,
			'user_email' => 'secupress_no_mail@fakemail.' . time(),
			'role'       => 'secupress_no_role_' . time(),
		) );
		if ( ! is_wp_error( $temp_id ) ) {

			$check = wp_authenticate( $temp_login, $temp_pass );

			wp_delete_user( $temp_id ); //// mettre cet ID en TR et le delete au prochain reload au cas où (déjà eu le cas mais pas compris why)

			if ( is_a( $check, 'WP_User' ) ) {
				// bad
				$this->add_message( 200 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		if ( ! secupress_is_premium() ) {
			$settings = array( 'double-auth_type' => 'googleauth', 'double_auth_affected_role' => array() );
			$this->add_fix_message( 1 );
		} else {
			$settings = array( 'double-auth_type' => 'passwordless', 'double-auth_passwordless-type' => 'email', 'double_auth_affected_role' => array() );
			$this->add_fix_message( 2 );
		}
		secupress_activate_module( 'users-login', $settings );

		return parent::fix();
	}
}
