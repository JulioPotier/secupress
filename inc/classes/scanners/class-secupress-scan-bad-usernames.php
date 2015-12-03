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
		self::$title = __( 'Check if your users username are not blacklisted.', 'secupress' );
		self::$more  = __( 'Some usernames are known to be used for malicious usage, or created by bots.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All the user names are correct.', 'secupress' ),
			1   => __( 'Module activated: the users with a blacklisted username will be asked to change it.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%s</strong> user has a forbidden username: %s', '<strong>%s</strong> users have a forbidden username: %s', 'secupress' ),
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
			$settings = array( 'blacklist-logins_activate' => 1 );
			secupress_activate_module( 'users-login', $settings );
			// good
			$this->add_fix_message( 1 );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
