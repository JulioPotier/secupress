<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PhpVersion scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_PhpVersion extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION      = '1.0';
	const PHP_VER_MIN  = '5.5.30';
	const PHP_VER_BEST = '5.6.14';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = __( 'File System', 'secupress' );
		self::$title = __( 'Check if your installation is using a supported version of PHP.', 'secupress' );
		self::$more  = __( 'Every year, old PHP version are not supported, even for security patches, it\'s important to stay updated.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => sprintf( __( 'You are using <strong>PHP v%s</strong>.', 'secupress' ), phpversion() ),
			1   => sprintf( __( 'You are using <strong>PHP v%s</strong>, perfect!', 'secupress' ), phpversion() ),
			// warning
			100 => __( 'Unable to determine version of PHP.', 'secupress' ),
			// bad
			200   => sprintf( __( 'You are using <strong>PHP v%1$s</strong>, but the latest supported version is <strong>PHP v%2$s</strong>, and the best is <strong>PHP v%3$s</strong>.', 'secupress' ), phpversion(), self::PHP_VER_MIN, self::PHP_VER_BEST ),
			// cantfix
			300 => __( 'I can not fix this, you have to contact you host provider to ask him to <strong>upgrade you version of PHP</strong>.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		if ( version_compare( phpversion(), self::PHP_VER_MIN ) < 0 ) {
			$this->add_message( 200 );
		}

		// good
		if ( phpversion() == self::PHP_VER_BEST ) {
			$this->add_message( 1 );
		} else {
			$this->maybe_set_status( 0 );
		}

		return parent::scan();
	}


	public function fix() {

		$this->add_fix_message( 300 );

		return parent::fix();
	}


}
