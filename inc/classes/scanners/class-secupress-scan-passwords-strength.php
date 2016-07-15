<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

/**
 * Passwords Strength scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Passwords_Strength extends SecuPress_Scan implements SecuPress_Scan_Interface {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Priority.
	 *
	 * @var (string)
	 */
	public    static $prio    = 'high';

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = false;


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		self::$type      = __( '3rd party', 'secupress' );

		if ( defined( 'FTP_PASS' ) ) {
			self::$title = __( 'Test the strength of WordPress database and FTP passwords.', 'secupress' );
			self::$more  = __( 'The passwords of the database and FTP have to be strong to avoid a possible brute-force attack.', 'secupress' );
		} else {
			self::$title = __( 'Test the strength of WordPress database password.', 'secupress' );
			self::$more  = __( 'The password of the database has to be strong to avoid a possible brute-force attack.', 'secupress' );
		}
		$this->more_fix  = static::get_messages( 300 );
	}

	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'Database password seems strong enough.', 'secupress' ),
			1   => __( 'Database and FTP passwords seems strong enough.', 'secupress' ),
			// "bad"
			200 => __( '%s is <strong>empty</strong>!', 'secupress' ),
			201 => __( '%s is known to be <strong>too common</strong>.', 'secupress' ),
			202 => _n_noop( '%1$s is only <strong>%2$d character length</strong>. That is obviously too short!', '%1$s is only <strong>%2$d characters length</strong>.', 'secupress' ),
			203 => __( '%s is not <strong>complex</strong> enough.', 'secupress' ),
			// "cantfix"
			300 => __( 'I cannot fix this, you have to manually change your DB and/or FTP password in your server administration.', 'secupress' ),
			301 => __( 'I cannot fix this, you have to manually change your DB password in your server administration.', 'secupress' ),
			302 => __( 'I cannot fix this, you have to manually change your FTP password in your server administration.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		$has_ftp = defined( 'FTP_PASS' );

		// DB_PASSWORD.
		if ( '' === DB_PASSWORD ) {
			// "bad"
			$this->add_message( 200, array( '<code>DB_PASSWORD</code>' ) );
			$this->add_pre_fix_message( 301 );

		} elseif ( self::dictionary_attack( DB_PASSWORD ) ) {
			// "bad"
			$this->add_message( 201, array( '<code>DB_PASSWORD</code>' ) );
			$this->add_pre_fix_message( 301 );

		} elseif ( ( $len = strlen( DB_PASSWORD ) ) <= 6 ) {
			// "bad"
			$this->add_message( 202, array( $len, '<code>DB_PASSWORD</code>', $len ) );
			$this->add_pre_fix_message( 301 );

		} elseif ( count( count_chars( DB_PASSWORD, 1 ) ) < 5 ) {
			// "bad"
			$this->add_message( 203, array( '<code>DB_PASSWORD</code>' ) );
			$this->add_pre_fix_message( 301 );

		}

		// FTP_PASS.
		if ( $has_ftp ) {
			if ( '' === FTP_PASS ) {
					// "bad"
				$this->add_message( 200, array( '<code>FTP_PASS</code>' ) );
				$this->add_pre_fix_message( 302 );

			} elseif ( self::dictionary_attack( FTP_PASS ) ) {
					// "bad"
				$this->add_message( 201, array( '<code>FTP_PASS</code>' ) );
				$this->add_pre_fix_message( 302 );

			} elseif ( ( $len = strlen( FTP_PASS ) ) <= 6 ) {
					// "bad"
				$this->add_message( 202, array( $len, '<code>FTP_PASS</code>', $len ) );
				$this->add_pre_fix_message( 302 );

			} elseif ( count( count_chars( FTP_PASS, 1 ) ) < 5 ) {
					// "bad"
				$this->add_message( 203, array( '<code>FTP_PASS</code>' ) );
				$this->add_pre_fix_message( 302 );

			}
		}

		// "good"
		$this->maybe_set_status( $has_ftp ? 1 : 0 );

		return parent::scan();
	}


	/**
	 * Test if a password is in our dictionary.
	 *
	 * @since 1.0
	 *
	 * @param (string) $password The password to test.
	 *
	 * @return (bool)
	 */
	public static function dictionary_attack( $password ) {
		$dictionary = file( SECUPRESS_INC_PATH . 'data/10kmostcommon.data', FILE_IGNORE_NEW_LINES );
		return $dictionary ? in_array( $password, $dictionary, true ) : null;
	}
}
