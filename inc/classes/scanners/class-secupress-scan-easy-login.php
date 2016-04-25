<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Easy Login scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Easy_Login extends SecuPress_Scan implements SecuPress_Scan_Interface {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Priority.
	 *
	 * @var (string)
	 */
	public    static $prio    = 'high';

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	public    static $fixable = false;


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your login page is protected by double authentication or something like that (may be a custom script).', 'secupress' );
		self::$more     = __( 'The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.', 'secupress' );
		self::$more_fix = sprintf(
			__( 'This will activate the <strong>%1$s</strong> from the module %2$s.', 'secupress' ),
			__( 'PasswordLess Double Authentication', 'secupress' ),
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-double-auth_type">' . __( 'Users & Login', 'secupress' ) . '</a>'
		);
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'The login page seems to be protected by double authentication or a custom script.', 'secupress' ),
			1   => __( 'The <strong>PasswordLess Double Authentication</strong> has been activated for every role. Users will receive an email to log-in now.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to create a user to test the login authentication system.', 'secupress' ),
			// "bad"
			200 => __( 'Your login system is <strong>not strong enough</strong>, you need a <strong>double authentication system</strong>.', 'secupress' ),
			201 => __( 'The registration page is <strong>not protected</strong> from bots.', 'secupress' ),
			202 => sprintf( __( 'Our module <a href="%s">%s</a> could fix this.', 'secupress' ), esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-double-auth_type', __( 'PasswordLess', 'secupress' ) ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		$temp_login = uniqid( 'secupress' );
		$temp_pass  = wp_generate_password( 64 );
		$temp_id    = wp_insert_user( array(
			'user_login' => $temp_login,
			'user_pass'  => $temp_pass,
			'user_email' => 'secupress_no_mail_EL@fakemail.' . time(),
			'role'       => 'secupress_no_role_' . time(),
		) );
		if ( ! is_wp_error( $temp_id ) ) {

			$check = wp_authenticate( $temp_login, $temp_pass );

			wp_delete_user( $temp_id );

			if ( is_a( $check, 'WP_User' ) ) {
				// "bad"
				$this->add_message( 200 );
				$this->add_pre_fix_message( 202 );
			}
		} else {
			// "warning"
			$this->add_message( 100 );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {

		if ( secupress_is_pro() && function_exists( 'secupress_pro_fix_easy_login' ) ) {
			secupress_pro_fix_easy_login();
		}

		return parent::fix();
	}
}
