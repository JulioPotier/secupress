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

	protected static function init() {
		self::$title = __( 'Check if your users have correct username, not blacklisted, not the same as their display name.', 'secupress' );
		self::$more  = __( 'It is important to not have the same username and display name to protect your username and avoid simple brute-force attacks. Also some usernames are known to be used for malicious usage, or created by bots.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			201 => _n_noop( '<strong>%s</strong> user has similar username and display name: %s', '<strong>%s</strong> users have similar username and display name: %s', 'secupress' ),
		);
	}


	public function scan() {
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
	}
}
