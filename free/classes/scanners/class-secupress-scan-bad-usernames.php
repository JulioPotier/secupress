<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad Usernames scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_Usernames extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.2';


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
		$this->title    = __( 'Check if your usernames are disallowed.', 'secupress' );
		$this->more     = __( 'Some usernames are known to be used for malicious usage, or created by bots.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Forbid Usernames', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-blacklist-logins_activated">' . __( 'Users & Login', 'secupress' ) . '</a>'
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
			0   => __( 'All the usernames are correct.', 'secupress' ),
			1   => __( 'Module activated: the users with a disallowed username will be asked to change it.', 'secupress' ),
			// "bad"
			200 => _n_noop( '<strong>%1$s user</strong> has a disallowed username: %2$s', '<strong>%1$s users</strong> have a disallowed username: %2$s', 'secupress' ),
			// "cantfix"
			300 => __( 'The module is already activated. Let’s give your users some time to change their username.', 'secupress' ),
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
		return __( 'https://docs.secupress.me/article/133-bad-username-scan', 'secupress' );
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

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		global $wpdb;

		// Blacklisted names.
		$names  = static::get_blacklisted_usernames();
		$logins = $wpdb->get_col( "SELECT user_login from $wpdb->users WHERE user_login IN ( '$names' )" ); // WPCS: unprepared SQL ok.
		$ids    = count( $logins );

		// "bad"
		if ( $ids ) {
			$this->slice_and_dice( $logins, 10 );
			// 2nd param: 1st item is used for the noop if needed, the rest for sprintf.
			$this->add_message( 200, array( $ids, $ids, static::wrap_in_tag( $logins, 'strong' ) ) );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( $this->has_fix_action_part( 'fix' ) ) {
			$this->fix();
		}
		// "good"
		$this->add_fix_message( 1 );
		return parent::manual_fix();
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		global $wpdb;

		// Blacklisted names.
		$names = static::get_blacklisted_usernames();
		$ids   = $wpdb->get_col( "SELECT ID from $wpdb->users WHERE user_login IN ( '$names' )" ); // WPCS: unprepared SQL ok.

		if ( $ids ) {
			$activated = secupress_is_submodule_active( 'users-login', 'blacklist-logins' );

			if ( $activated ) {
				// Well... Can't do better.
				// "cantfix".
				$this->add_fix_message( 300 );
			} else {
				// Activate.
				secupress_activate_submodule( 'users-login', 'blacklist-logins' );
				// "good"
				$this->add_fix_message( 1 );
			}
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/** Tools. ================================================================================== */

	/**
	 * Get the blacklisted usernames.
	 *
	 * @since 1.0
	 *
	 * @return (string) A comma separated list of blacklisted usernames.
	 */
	final protected static function get_blacklisted_usernames() {
		$list = secupress_get_blacklisted_usernames();
		return implode( "','", esc_sql( $list ) );
	}
}
