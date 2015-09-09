<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PHP Disclosure scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_PHP_Disclosure extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'php_disclosure';
	public    static $prio = 'low';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses the PHP modules <em>(know as PHP Easter Egg)</em>.', 'secupress' );
		self::$more  = __( 'Don\'t let them easily find these informations.', 'secupress' ); ////
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'Your site doesn\'t reveal the PHP modules.', 'secupress' ),
			// warning
			100 => sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ) ),
			// bad
			200 => sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ) ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$response = wp_remote_get( home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) && $body = wp_remote_retrieve_body( $response ) ) {

			if ( strpos( $body, '<h1>PHP Credits</h1>' ) > 0 && strpos( $body, '<title>phpinfo()</title>' ) > 0 ) {
				// bad
				$this->add_message( 200 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		// good
		$this->maybe_set_status();

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
