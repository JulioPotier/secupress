<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Passwords Strength scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Passwords_Strength extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.1';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = false;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		if ( defined( 'FTP_PASS' ) ) {
			$this->title = __( 'Test the strength of WordPress database and FTP passwords.', 'secupress' );
			$this->more  = __( 'The passwords of the database and FTP have to be strong to avoid a possible brute-force attack.', 'secupress' );
		} else {
			$this->title = __( 'Test the strength of WordPress database password.', 'secupress' );
			$this->more  = __( 'The password of the database has to be strong to avoid a possible brute-force attack.', 'secupress' );
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
			200 => __( 'Your Database password is <strong>empty</strong>, this is not secure!', 'secupress' ),
			201 => __( 'Your Database password is known to be <strong>too common</strong>, this is not secure', 'secupress' ),
			202 => _n_noop( 'Your Database password is only <strong>%d character length</strong>, this is not secure', 'Your Database password is only <strong>%d characters length</strong>, this is not secure', 'secupress' ),
			203 => __( 'Your Database password is not <strong>complex</strong> enough, this is not secure', 'secupress' ),
			210 => __( 'Your FTP password is <strong>empty</strong>, this is not secure!', 'secupress' ),
			211 => __( 'Your FTP password is known to be <strong>too common</strong>, this is not secure', 'secupress' ),
			212 => _n_noop( 'Your FTP password is only <strong>%d character length</strong>, this is not secure', 'Your FTP password is only <strong>%d characters length</strong>, this is not secure', 'secupress' ),
			213 => __( 'Your FTP password is not <strong>complex</strong> enough, this is not secure', 'secupress' ),
			// "cantfix"
			300 => __( 'This cannot be fixed automatically, you have to manually change your database and FTP password in your server administration.', 'secupress' ),
			301 => __( 'This cannot be fixed automatically, you have to manually change your database password in your server administration.', 'secupress' ),
			302 => __( 'This cannot be fixed automatically, you have to manually change your FTP password in your server administration.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/131-ftp-and-database-passwords-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		$has_ftp = defined( 'FTP_PASS' );

		// DB_PASSWORD.
		if ( '' === DB_PASSWORD ) {
			// "bad"
			$this->add_message( 200 );
			$this->add_pre_fix_message( 301 );

		} elseif ( self::dictionary_attack( DB_PASSWORD ) ) {
			// "bad"
			$this->add_message( 201 );
			$this->add_pre_fix_message( 301 );

		} elseif ( ( $len = strlen( DB_PASSWORD ) ) <= 6 ) {
			// "bad"
			$this->add_message( 202 );
			$this->add_pre_fix_message( 301 );

		} elseif ( count( count_chars( DB_PASSWORD, 1 ) ) < 5 ) {
			// "bad"
			$this->add_message( 203 );
			$this->add_pre_fix_message( 301 );

		}

		// FTP_PASS.
		if ( $has_ftp ) {
			if ( '' === FTP_PASS ) {
					// "bad"
				$this->add_message( 210 );
				$this->add_pre_fix_message( 302 );

			} elseif ( self::dictionary_attack( FTP_PASS ) ) {
					// "bad"
				$this->add_message( 211 );
				$this->add_pre_fix_message( 302 );

			} elseif ( ( $len = strlen( FTP_PASS ) ) <= 6 ) {
					// "bad"
				$this->add_message( 212 );
				$this->add_pre_fix_message( 302 );

			} elseif ( count( count_chars( FTP_PASS, 1 ) ) < 5 ) {
					// "bad"
				$this->add_message( 213 );
				$this->add_pre_fix_message( 302 );

			}
		}

		// "good"
		$this->maybe_set_status( $has_ftp ? 1 : 0 );

		return parent::scan();
	}


	/** Tools. ================================================================================== */

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
