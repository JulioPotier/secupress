<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad User Agent scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_User_Agent extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'bad_user_agent';
	public    static $prio = 'high';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if bad user-agent can visit your website.', 'secupress' );
		self::$more  = __( '////?', 'secupress' );
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently blocking bad user-agents.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => sprintf( __( 'Your website should block <code>%s</code> requests with <strong>bad user-agents</strong>.', 'secupress' ), 'HTTP' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$response = wp_remote_get( home_url(), array( 'redirection' => 0, 'user-agent' => '<script>' ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 200 );
			} else {
				// good
				$this->add_message( 0 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
