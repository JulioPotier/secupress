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
		self::$more  = __( 'It is important to not have the same login and display name to protect your login name and avoid simple brute-force attacks. Also some usernames are know to be used for malicious usage, or created by bots.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All the user names are correct.', 'secupress' ),
			1   => __( 'Module activated: the users with a blacklisted username will be asked to change it.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%s</strong> user has a forbidden login name: %s', '<strong>%s</strong> users have a forbidden login name: %s', 'secupress' ),
			201 => _n_noop( '<strong>%s</strong> user has similar login name and display name: %s', '<strong>%s</strong> users have similar login name and display name: %s', 'secupress' ),
			// cantfix
			//// 300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		// Blacklisted names
		$names  = "'" . secupress_blacklist_logins_list_default( "','" ) . "'";
		$logins = $wpdb->get_col( "SELECT user_login from $wpdb->users WHERE user_login IN ( $names )" );
		$ids    = count( $logins );

		// bad
		if ( $ids ) {
			if ( $ids > 10 ) {
				$logins = array_slice( $logins, 0, 9 );
				array_push( $logins, '&hellip;' );
			}
			// 2nd param: 1st item is used for the noop if needed, the rest for sprintf.
			$this->add_message( 200, array( $ids, $ids, static::wrap_in_tag( $logins, 'strong' ) ) );
		}

		// Who have the same nickname and login?
		$logins = $wpdb->get_col( "SELECT user_login FROM $wpdb->users u, $wpdb->usermeta um WHERE u.user_login = u.display_name OR ( um.user_id = u.ID AND um.meta_key = 'nickname' AND um.meta_value = u.user_login ) GROUP BY user_login" );
		$ids    = count( $logins );

		// bad
		if ( $ids ) {
			if ( $ids > 10 ) {
				$logins = array_slice( $logins, 0, 9 );
				array_push( $logins, '&hellip;' );
			}
			// 2nd param: 1st item is used for the noop if needed, the rest for sprintf.
			$this->add_message( 201, array( $ids, $ids, static::wrap_in_tag( $logins, 'strong' ) ) );
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
