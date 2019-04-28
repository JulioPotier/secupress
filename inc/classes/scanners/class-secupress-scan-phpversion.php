<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PhpVersion scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_PhpVersion extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.1.1';


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
		$this->title    = __( 'Check if your installation is using a supported version of PHP.', 'secupress' );
		$this->more     = __( 'Every year old PHP version are not supported anymore, even for security patches so it\'s important to stay updated.', 'secupress' );
		$this->more_fix = static::get_messages( 300 );
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
		$versions = static::get_php_versions();
		$messages = array(
			// "good"
			0   => sprintf( __( 'You are using <strong>PHP v%s</strong>.', 'secupress' ), $versions['current'] ),
			1   => sprintf( __( 'You are using <strong>PHP v%s</strong>, perfect!', 'secupress' ), $versions['current'] ),
			// "warning"
			100 => __( 'Unable to determine version of PHP.', 'secupress' ),
			// "bad"
			200   => sprintf( __( 'You are using <strong>PHP v%1$s</strong>, but the latest supported version is <strong>PHP v%2$s</strong>, and the best is <strong>PHP v%3$s</strong>.', 'secupress' ), $versions['current'], $versions['mini'], $versions['best'] ),
			// "cantfix"
			300 => __( 'Cannot be fixed automatically. You have to contact you host provider to ask him to <strong>upgrade you version of PHP</strong>.', 'secupress' ),
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
		return __( 'http://docs.secupress.me/article/114-php-version-scan', 'secupress' );
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

		$activated = secupress_filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		$versions = static::get_php_versions();

		if ( version_compare( $versions['current'], $versions['mini'] ) < 0 ) {
			$this->add_message( 200 );
			$this->add_pre_fix_message( 300 );
		}

		// "good"
		if ( $versions['current'] === $versions['best'] ) {
			$this->add_message( 1 );
		} else {
			$this->maybe_set_status( 0 );
		}

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		$this->add_fix_message( 300 );
		return parent::fix();
	}


	/** Tools. ================================================================================== */

	/**
	 * Get the 3 php versions we need: current, mini, and best.
	 *
	 * @since 1.0
	 *
	 * @return (array) The 3 php versions with the following keys: "current", "mini", "best".
	 */
	public static function get_php_versions() {
		static $versions;

		if ( isset( $versions ) ) {
			return $versions;
		}

		$versions = array(
			'current' => phpversion(),
			'mini'    => '7.1.28',
			'best'    => '7.3.4',
		);

		if ( false === ( $php_vers = get_site_transient( 'secupress_php_versions' ) ) ) {
			$response = wp_remote_get( 'http://php.net/releases/index.php?json&version=7&max=2' );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$php_vers = json_decode( wp_remote_retrieve_body( $response ) );
				$php_vers = array_keys( (array) $php_vers );
				set_site_transient( 'secupress_php_versions', $php_vers, 7 * DAY_IN_SECONDS );
			}
		}

		if ( $php_vers ) {
			$versions['mini'] = end( $php_vers );
			$versions['best'] = reset( $php_vers );
		}

		return $versions;
	}
}
