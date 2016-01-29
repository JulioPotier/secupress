<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Subscription scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Subscription extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if the subscription settings are set correctly.', 'secupress' );
		self::$more  = __( 'If user registrations are open, the default user role should be Subscriber. Moreover, your registration page should be protected from bots.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your subscription settings are set correctly.', 'secupress' ),
			1   => __( 'A captcha module has been activated to block bot registration.', 'secupress' ),
			2   => __( 'The user role for new registrations has been set to <strong>Subscriber</strong>.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => __( 'The default role in your installation is <strong>%s</strong> and it should be <strong>Subscriber</strong>, or registrations should be <strong>closed</strong>.', 'secupress' ),
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
		global $wp_roles;

		// Open subscriptions
		if ( get_option( 'users_can_register' ) ) {

			// Default role
			$role = get_option( 'default_role' );

			if ( 'subscriber' !== $role ) {
				// bad
				$role = isset( $wp_roles->role_names[ $role ] ) ? translate_user_role( $wp_roles->role_names[ $role ] ) : __( 'None' );
				$this->add_message( 200, array( $role ) );
			}

			// Bots
			$user_login = 'secupress_' . time();
			$response   = wp_remote_post( wp_registration_url(), array(
				'body' => array(
					'user_login' => $user_login,
					'user_email' => 'secupress_no_mail@fakemail.' . time(),
				),
			) );

			if ( ! is_wp_error( $response ) ) {

				if ( $user_id = username_exists( $user_login ) ) {

					wp_delete_user( $user_id );

					if ( 'failed' === get_transient( 'secupress_registration_test' ) ) {
						// bad
						$this->add_message( 201 );
					}
				}

			} else {
				// warning
				$this->add_message( 100 );
			}

			delete_transient( 'secupress_registration_test' );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		if ( ! get_option( 'users_can_register' ) ) {
			return parent::fix();
		}

		// Default role
		if ( 'subscriber' !== get_option( 'default_role' ) ) {
			update_option( 'default_role', 'subscriber' );
			// good
			$this->add_fix_message( 2 );
		}

		// Bots: use a captcha.
		secupress_activate_submodule( 'users-login', 'login-captcha' );

		// good
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
