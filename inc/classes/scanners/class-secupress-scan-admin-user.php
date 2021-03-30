<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Admin User scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Admin_User extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.1';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$current_user = wp_get_current_user();

		$this->title = __( 'Check if the <em>admin</em> account is correctly protected.', 'secupress' );
		$this->more  = __( 'It is important to protect the famous <em>admin</em> account to prevent simple brute-force attacks on it. This account is usually the first one created when you install WordPress, and it is well known by attackers.', 'secupress' );

		if ( 'admin' === $current_user->user_login ) {
			$this->more_fix = __( 'You will be asked for a new username and your account will be renamed.', 'secupress' );
		} else {
			$this->more_fix = __( 'Remove all roles and capabilities from the <em>admin</em> account if it exists. If it does not exist and user subscriptions are open, the account will be created with no role nor capabilities.', 'secupress' );
		}
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
			0   => __( 'The %s account is correctly protected.', 'secupress' ),
			1   => __( 'The %s account has no role anymore.', 'secupress' ),
			// "warning"
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			// "bad"
			200 => __( 'The %s account should have no role at all.', 'secupress' ),
			201 => __( 'Because user registrations are open, the %s account should exist (with no role) to prevent someone from registering it.', 'secupress' ),
			202 => __( 'Sorry, the username %s is forbidden!', 'secupress' ),
			203 => __( 'Cannot create a user with an empty login name!' ), // WPi18n.
			204 => __( 'Sorry, the username %s already exists!', 'secupress' ),
			205 => __( 'The username %1$s is invalid because it uses illegal characters. Spot the differences: %2$s.', 'secupress' ),
			206 => __( 'Sorry, the role cannot be removed from the %s account. You should try to remove it manually.', 'secupress' ),
			207 => __( 'Sorry, the %s account could not be created. You should try to create it manually and then remove its role.', 'secupress' ),
			// "cantfix"
			300 => __( 'Oh! The %s account is yours! Please choose a new login for your account in the next step.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/132-admin-user-account-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$username = 'admin';

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0, array( '<em>' . $username . '</em>' ) );
			return parent::scan();
		}

		if ( secupress_get_site_transient( 'secupress-rename-admin-username' ) ) {
			$this->add_message( 100 );
			return parent::scan();
		}

		$user_id  = username_exists( $username );

		// The "admin" account exists and has a role or capabilities: it should have no role.
		if ( static::user_has_capas( $user_id ) ) {
			// "bad"
			$this->add_message( 200, array( '<em>' . $username . '</em>' ) );
		}

		// The "admin" account should exist to avoid its creation when users can register.
		if ( ! $user_id && secupress_users_can_register() ) {
			// "bad"
			$this->add_message( 201, array( '<em>' . $username . '</em>' ) );
		}

		// "good"
		$this->maybe_set_status( 0, array( '<em>' . $username . '</em>' ) );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		global $wpdb;

		$username = 'admin';
		$user_id  = username_exists( $username );

		// The "admin" account exists and has a role or capabilities.
		if ( static::user_has_capas( $user_id ) ) {

			$current_user_id = get_current_user_id();

			// It's not you: remove all roles and capabilities.
			if ( $user_id !== $current_user_id ) {
				// Remove all capabilities.
				$wpdb->query( $wpdb->prepare( "DELETE FROM $wpdb->usermeta WHERE user_id = %d AND meta_key REGEXP '{$wpdb->base_prefix}([0-9]+_)?capabilities'", $user_id ) );

				if ( is_multisite() ) {
					// Not a network administrator anymore.
					revoke_super_admin( $user_id );
				}

				if ( static::user_has_capas( $user_id ) ) {
					// "bad"
					$this->add_fix_message( 206, array( '<em>' . $username . '</em>' ) );
				} else {
					// "good"
					$this->add_fix_message( 1, array( '<em>' . $username . '</em>' ) );
				}
			}
			// It's you, you must change your username.
			else {
				// This fix requires the user to take action.
				$this->add_fix_message( 300, array( '<em>' . $username . '</em>' ) );
			}
		}

		// Registrations are open: the "admin" account should exist to avoid the creation of this user.
		if ( ! $user_id && secupress_users_can_register() ) {
			// Make sure our "admin" creation is not blocked by our usernames blacklist.
			secupress_cache_data( 'allowed_usernames', $username );
			$user_id = wp_insert_user( array(
				'user_login' => $username,
				'user_pass'  => wp_generate_password( 64, 1, 1 ),
				'user_email' => 'secupress_no_mail_AU@fakemail.' . time(),
				'role'       => '',
			) );
			secupress_cache_data( 'allowed_usernames', array() );

			if ( is_wp_error( $user_id ) || ! $user_id ) {
				// "bad"
				$this->add_fix_message( 207, array( '<em>' . $username . '</em>' ) );
			} else {
				if ( is_multisite() ) {
					// Make sure the new user is not a network administrator.
					revoke_super_admin( $user_id );
				}
				// "good"
				$this->add_fix_message( 0, array( '<em>' . $username . '</em>' ) );
			}
		}

		// "good"
		$this->maybe_set_fix_status( 0, array( '<em>' . $username . '</em>' ) );

		return parent::fix();
	}


	/** Manual fix. ============================================================================= */

	/**
	 * Return an array of actions if a manual fix is needed here.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function need_manual_fix() {
		$user_id   = username_exists( 'admin' );
		$has_capas = static::user_has_capas( $user_id );

		// The "admin" account exists but has no role or capabilities.
		if ( $user_id && ! $has_capas ) {
			// OK.
			return array();
		}

		// The "admin" account exists and has a role or capabilities.
		if ( $has_capas ) {
			// It's you! Manual fix.
			if ( get_current_user_id() === $user_id ) {
				return array( 'rename-admin-username' => 'rename-admin-username' );
			}
			// It's not you: automatic fix.
			return false;
		}

		// Registrations are open: the "admin" account should exist to avoid the creation of this user.
		if ( ! $user_id && secupress_users_can_register() ) {
			// Automatic fix.
			return false;
		}

		// OK.
		return array();
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'rename-admin-username' ) ) {
			return parent::manual_fix();
		}

		$username = ! empty( $_POST['secupress-fix-rename-admin-username'] ) ? sanitize_user( $_POST['secupress-fix-rename-admin-username'] ) : null; // WPCS: CSRF ok.

		if ( 'admin' === $username ) {
			// "bad"
			$this->add_fix_message( 202, array( '<em>' . $username . '</em>' ) );
		} elseif ( ! $username ) {
			// "bad"
			$this->add_fix_message( 203 );
		} elseif ( username_exists( $username ) ) {
			// "bad"
			$this->add_fix_message( 204, array( '<em>' . $username . '</em>' ) );
		} elseif ( sanitize_user( $username, true ) !== $username ) {
			// "bad"
			$this->add_fix_message( 205, array( '<em>' . $username . '</em>', '<em>' . sanitize_user( $username, true ) . '</em>' ) );
		} else {
			// $username ok, can't rename now or all nonces will be broken and the user disconnected
			$current_user_id = get_current_user_id();
			secupress_set_site_transient( 'secupress-rename-admin-username', array( 'ID' => $current_user_id, 'username' => $username ) );
			// "warning"
			$this->add_fix_message( 100 );
		}

		return parent::manual_fix();
	}


	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		$form  = '<h4>' . __( 'Choose a new login for your account:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Your username will be renamed on the next page load.', 'secupress' ) . '</span></p>';
		$form .= '<input type="text" id="secupress-fix-rename-admin-username" name="secupress-fix-rename-admin-username" value="admin_' . substr( md5( time() ), 0, 6 ) . '"/>';
		$form .= '<p>' . sprintf( __( 'Allowed characters: %s.', 'secupress' ), '<code>A-Z, a-z, 0-9, _, ., -, @</code>' ) . '</p>';

		return array( 'rename-admin-username' => $form );
	}


	/** Tools. ================================================================================== */

	/**
	 * Tell if a user has a role, capabilities, or is network admin.
	 *
	 * @since 1.0
	 *
	 * @param (int) $user_id The user ID.
	 *
	 * @return (bool)
	 */
	protected static function user_has_capas( $user_id ) {
		global $wpdb;

		if ( ! $user_id ) {
			return false;
		}

		if ( is_super_admin( $user_id ) ) {
			return true;
		}

		// Get all user metas "wp_capabilities",  "wp_2_capabilities" (MS)...
		$caps = $wpdb->get_var( $wpdb->prepare( "SELECT meta_key FROM $wpdb->usermeta WHERE user_id = %d AND meta_value != 'a:0:{}' AND meta_key REGEXP '{$wpdb->base_prefix}([0-9]+_)?capabilities' LIMIT 1", $user_id ) );

		return (bool) $caps;
	}
}
