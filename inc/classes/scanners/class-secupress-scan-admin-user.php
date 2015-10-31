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
			0   => __( 'The %s account is correctly protected.', 'secupress' ),
			1   => __( 'The %s account is not an Administrator anymore.', 'secupress' ),
			// warning
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			// bad
			200 => __( 'The %s account role should not be <strong>Administrator</strong> but should have no role at all.', 'secupress' ),
			201 => __( 'Because the user registration is open, the %s account should exist (with no role) to avoid someone to register it.', 'secupress' ),
			202 => __( 'Sorry, the username %s is forbidden!', 'secupress' ),
			203 => __( 'Cannot create a user with an empty login name!' ), // WPi18n
			204 => __( 'Sorry, the username %s already exists!', 'secupress' ),
			205 => __( 'The username %s is invalid because it uses illegal characters.', 'secupress' ),
			206 => __( 'Sorry, I couldn\'t remove the <strong>Administrator</strong> role from the %s account. You should try to remove its role manually.', 'secupress' ),
			207 => __( 'Sorry, the %s account could not be created. You should try to create it manually and then remove its role.', 'secupress' ),
			// cantfix
			300 => __( 'Oh! The %s account is yours! Please choose a new login for your account.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$username = 'admin';
		$check    = username_exists( $username );

		if ( get_transient( 'secupress-rename-admin-username' ) ) {
			$this->add_message( 100 );
		} else {
			// Should not be administrator.
			if ( false !== $check && user_can( $check, 'administrator' ) ) {
				// bad
				$this->add_message( 200, array( '<em>' . $username . '</em>' ) );
			}

			// // "admin" user should exist to avoid the creation of this user.
			if ( get_option( 'users_can_register' ) && false === $check ) {
				// bad
				$this->add_message( 201, array( '<em>' . $username . '</em>' ) );
			}
		}
		// good
		$this->maybe_set_status( 0, array( '<em>' . $username . '</em>' ) );

		return parent::scan();
	}


	public function fix() {

		$username     = 'admin';
		$check        = username_exists( $username );
		$current_user = wp_get_current_user();

		// Should not be administrator.
		if ( false !== $check && user_can( $check, 'administrator' ) ) {
			if ( $check != $current_user->ID ) {
				$user = new WP_User( $check );
				$user->remove_role( 'administrator' );

				if ( user_can( $user, 'administrator' ) ) {
					// bad
					$this->add_fix_message( 206, array( '<em>' . $username . '</em>' ) );
				} else {
					// good
					$this->add_fix_message( 1, array( '<em>' . $username . '</em>' ) );
				}
			} else {
				// This fix requires the user to take action.
				$this->add_fix_message( 300, array( '<em>' . $username . '</em>' ) );
				$this->add_fix_action( 'rename-admin-username' );
			}
		}

		// "admin" user should exist to avoid the creation of this user.
		if ( false === $check && get_option( 'users_can_register' ) ) {
			$user_id = wp_insert_user( array(
				'user_login' => $username,
				'user_pass'  => wp_generate_password( 64, 1, 1 ),
				'user_email' => 'secupress_no_mail@fakemail.' . time(),
				'role'       => '',
			) );

			if ( is_wp_error( $user_id ) || ! $user_id ) {
				// bad
				$this->add_fix_message( 207, array( '<em>' . $username . '</em>' ) );
			} else {
				// good
				$this->add_fix_message( 0, array( '<em>' . $username . '</em>' ) );
			}
		}

		// good
		$this->maybe_set_fix_status( 0, array( '<em>' . $username . '</em>' ) );

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'rename-admin-username' ) ) {
			return parent::manual_fix();
		}

		$username = ! empty( $_POST['secupress-fix-rename-admin-username'] ) ? sanitize_user( $_POST['secupress-fix-rename-admin-username'] ) : null;

		if ( 'admin' === $username ) {
			// bad
			$this->add_fix_message( 202, array( '<em>' . $username . '</em>' ) );
			$this->add_fix_action( 'rename-admin-username' );
		} elseif ( ! $username ) {
			// bad
			$this->add_fix_message( 203 );
			$this->add_fix_action( 'rename-admin-username' );
		} elseif ( username_exists( $username ) ) {
			// bad
			$this->add_fix_message( 204, array( '<em>' . $username . '</em>' ) );
			$this->add_fix_action( 'rename-admin-username' );
		} elseif ( $username !== sanitize_user( $username, true ) ) {
			// bad
			$this->add_fix_message( 205, array( '<em>' . $username . '</em>' ) );
			$this->add_fix_action( 'rename-admin-username' );
		} else {
			// $username ok, can't rename now or all nonces will be broken and the user disconnected
			$current_user = wp_get_current_user();
			set_transient( 'secupress-rename-admin-username', array( 'ID' => $current_user->ID, 'username' => $username ) );
			// warning
			$this->add_fix_message( 100 );
		}

		return parent::manual_fix();
	}

	protected function get_fix_action_template_parts() {
		$form  = '<h4>' . __( 'Choose a new login for your account:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Your username will be renamed on the next page change.', 'secupress' ) . '</span></p>';
		$form .= '<input type="text" id="secupress-fix-rename-admin-username" name="secupress-fix-rename-admin-username" value="admin_' . substr( md5( time() ), 0, 6 ) . '"/>';
		$form .= '<p>' . sprintf( __( 'Allowed characters: %s.', 'secupress' ), '<code>A-Z, a-z, 0-9, _, ., -, @</code>' ) . '</p>';

		return array( 'rename-admin-username' => $form );
	}
}
