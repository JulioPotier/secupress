<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Usernames scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Usernames extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your users have correct username, not blacklisted, not the same as their login.', 'secupress' );
		self::$more  = __( 'It is important to not have the same login and display name to protect your login name and avoid simple brute-force attacks.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All the user names are correct.', 'secupress' ),
			1   => __( 'Module activated: the users with a blacklisted username will be asked to change it.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d</strong> user has a forbidden login name.', '<strong>%d</strong> users have a forbidden login name.', 'secupress' ),
			201 => _n_noop( '<strong>%d</strong> user has similar login name and display name.', '<strong>%d</strong> users have similar login name and display name.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		// Blacklisted names
		$names = "'" . secupress_blacklist_logins_list_default( "','" ) . "'";
		$ids   = $wpdb->get_col( "SELECT ID from $wpdb->users WHERE user_login IN ( $names )" );
		$ids   = count( $ids );

		if ( $ids ) {
			// bad
			$this->add_message( 200, array( $ids, number_format_i18n( $ids ) ) );
		}

		// Who have the same nickname and login?
		$ids = $wpdb->get_col( "SELECT ID FROM $wpdb->users u, $wpdb->usermeta um WHERE u.user_login = u.display_name OR ( um.user_id = u.ID AND um.meta_key = 'nickname' AND um.meta_value = u.user_login ) GROUP BY ID" );
		$ids = count( $ids );

		if ( $ids ) {
			// bad
			$this->add_message( 201, array( $ids, number_format_i18n( $ids ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $wpdb;

		// Blacklisted names
		$names = "'" . secupress_blacklist_logins_list_default( "','" ) . "'";
		$ids   = $wpdb->get_col( "SELECT ID from $wpdb->users WHERE user_login IN ( $names )" );

		if ( $ids ) {
			$settings = array( 'bad-logins_blacklist-logins' => '1' );
			secupress_activate_module( 'users-login', $settings );
			// good
			$this->add_fix_message( 1 );
		}

		// Who have the same nickname and login?
		////

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
