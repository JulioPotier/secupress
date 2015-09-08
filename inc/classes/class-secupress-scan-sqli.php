<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * SQLi scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_SQLi extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'sqli';
	public    static $prio = 'high';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if a basic SQL Injection is blocked or not.', 'secupress' );
		self::$more  = __( '////?', 'secupress' );
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently blocking simple SQL Injection.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => __( 'Your website should block <strong>malicious requests</strong>.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$response = wp_remote_get( home_url( '/?' . time() . '=UNION+SELECT+FOO' ), array( 'redirection' => 0 ) );

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
