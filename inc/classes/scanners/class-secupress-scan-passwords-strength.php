<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Passwords Strength scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Passwords_Strength extends SecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = __( '3rd party', 'secupress' );

		if ( defined( 'FTP_PASS' ) ) {
			self::$title = __( 'Test the strength of WordPress database and FTP passwords.', 'secupress' );
			self::$more  = __( 'The passwords of the database and FTP have to be strong to avoid a possible brute-force attack.', 'secupress' );
		} else {
			self::$title = __( 'Test the strength of WordPress database password.', 'secupress' );
			self::$more  = __( 'The password of the database has to be strong to avoid a possible brute-force attack.', 'secupress' );
		}
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Database password is strong enough.', 'secupress' ),
			1   => __( 'Database and FTP passwords are strong enough.', 'secupress' ),
			// bad
			200 => __( '%s is <strong>empty</strong>!', 'secupress' ),
			201 => __( '%s is known to be <strong>too common</strong>.', 'secupress' ),
			202 => _n_noop( '%1$s is only <strong>%2$d character length</strong>. That is obviously too short!', '%1$s is only <strong>%2$d characters length</strong>.', 'secupress' ),
			203 => __( '%s is not <strong>complex</strong> enough.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to manually change your DB and/or FTP password in your server administration.', 'secupress' ), //// and/or ? better ?
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$has_ftp = defined( 'FTP_PASS' );

		// DB_PASSWORD
		if ( '' === DB_PASSWORD ) {
			// bad
			$this->add_message( 200, array( '<code>DB_PASSWORD</code>' ) );

		} elseif ( self::dictionary_attack( DB_PASSWORD ) ) {
			// bad
			$this->add_message( 201, array( '<code>DB_PASSWORD</code>' ) );

		} elseif ( ( $len = strlen( DB_PASSWORD ) ) <= 6 ) {
			// bad
			$this->add_message( 202, array( $len, '<code>DB_PASSWORD</code>', $len ) );

		} elseif ( sizeof( count_chars( DB_PASSWORD, 1 ) ) < 5 ) {
			// bad
			$this->add_message( 203, array( '<code>DB_PASSWORD</code>' ) );

		}

		// FTP_PASS
		if ( $has_ftp ) {
			if ( '' === FTP_PASS ) {
					// bad
				$this->add_message( 200, array( '<code>FTP_PASS</code>' ) );

			} elseif ( self::dictionary_attack( FTP_PASS ) ) {
					// bad
				$this->add_message( 201, array( '<code>FTP_PASS</code>' ) );

			} elseif ( ( $len = strlen( FTP_PASS ) ) <= 6 ) {
					// bad
				$this->add_message( 202, array( $len, '<code>FTP_PASS</code>', $len ) );

			} elseif ( sizeof( count_chars( FTP_PASS, 1 ) ) < 5 ) {
					// bad
				$this->add_message( 203, array( '<code>FTP_PASS</code>' ) );

			}
		}

		// good
		$this->maybe_set_status( $has_ftp ? 1 : 0 );

		return parent::scan();
	}


	public function fix() {

		$this->add_fix_message( 300 );

		return parent::fix();
	}


	public static function dictionary_attack( $password ) {
		$dictionary = file( SECUPRESS_INC_PATH . 'data/10kmostcommon.data', FILE_IGNORE_NEW_LINES );
		return $dictionary ? in_array( $password, $dictionary ) : null;
	}
}
