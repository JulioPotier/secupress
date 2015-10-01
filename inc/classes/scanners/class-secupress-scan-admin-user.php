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
			// warning
			100 => __( 'This fix is <b>pending</b>, please reload the page to apply it now.', 'secupress' ),
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

		if ( get_transient( 'secupress-rename-admin-username' ) ) {
			$this->add_message( 100 );
		} else {
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
		}
		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		$check = username_exists( 'admin' );
		$current_user = wp_get_current_user();

		// Should not be administrator.
		if ( false !== $check && user_can( $check, 'administrator' ) ) {
			if ( $check != $current_user->ID ) {
				$user = new WP_User( $check );
				$user->remove_role( 'administrator' );
			} else {
				$this->add_fix_action( 'rename-admin-username' );
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


	public function manual_fix() {
		$username = ! empty( $_POST['secupress-fix-rename-admin-username'] ) ? sanitize_user( $_POST['secupress-fix-rename-admin-username'] ) : null;
		if ( $this->has_fix_action_part( 'rename-admin-username' ) ) {
			if ( 'admin' == $username ) {
				return array( 'code' => 'error', 'message' => __( 'Sorry, that username is forbidden!' ) );
			} elseif ( is_null( $username ) || '' == $username ) {
				return array( 'code' => 'error', 'message' => __( 'Cannot create a user with an empty login name.!' ) );
			} elseif ( username_exists( $username ) ) {
				return array( 'code' => 'error', 'message' => __( 'Sorry, that username already exists!' ) );
			} elseif ( $username != sanitize_user( $username, true ) ) {
				return array( 'code' => 'error', 'message' => __( 'This username is invalid because it uses illegal characters.' ) );
			}
			// $username ok, can't rename now or all nonces will be broken and the user disconnected
			$current_user = wp_get_current_user();
			set_transient( 'secupress-rename-admin-username', array( 'ID' => $current_user->ID, 'username' => $username ) );
		}

		return $this->scan();
	}

	public function get_fix_action_template_parts() {
		$form  = '<div class="show-input">';
		$form .= '<h4>' . __( 'Choose a new login for your account:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Your username will be renamed on the next page change.', 'secupress' ) . '</span></p>';
		$form .= '<input type="text" id="secupress-fix-rename-admin-username" name="secupress-fix-rename-admin-username" value="admin_' . substr( md5( time() ), 0, 6 ) . '"/>';
		$form .= '<br>' . sprintf( __( 'Allowed chars: %s', 'secupress' ), '<code>A-Z, a-z, 0-9, _, ., -, @</code>' );
		$form .= '</div>';

		return array( 'rename-admin-username' => $form );
	}
}
