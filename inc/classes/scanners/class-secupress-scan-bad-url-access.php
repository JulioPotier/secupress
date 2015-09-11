<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad URL Access scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_URL_Access extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'bad_url_access';
	public    static $prio = 'medium';


	public function __construct() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses sensitive informations.', 'secupress' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your site doesn\'t reveal sensitive informations.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => _n_noop( '%s shouldn\'t be accessible by anyone.', '%s shouldn\'t be accessible by anyone.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		remove_all_filters( 'site_url' ); // avoid plugin's hooks of course
		remove_all_filters( 'admin_url' ); // avoid plugin's hooks of course

		$urls = array(
			site_url( 'wp-login.php', 'login' ),
			home_url( 'php.ini' ),
			admin_url( 'install.php' ),
			admin_url( 'menu-header.php' ),
			admin_url( 'includes/menu.php' ),
		);
		$bads     = array();
		$warnings = array();

		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, array( 'redirection' => 0 ) );

			if ( ! is_wp_error( $response ) ) {

				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					// bad
					$bads[] = '<code>' . $url . '</code>';
				}

			} else {
				// warning
				$warnings[] = '<code>' . $url . '</code>';
			}
		}

		if ( $bads ) {
			// bad
			$this->add_message( 200, array( count( $bads ), wp_sprintf_l( '%l', $bads ) ) );
		}

		if ( $warnings ) {
			// warning
			$this->add_message( 100, array( count( $warnings ), wp_sprintf_l( '%l', $warnings ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
