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
	public    static $prio         = 'medium';

	/**
	 * Minimum php version.
	 *
	 * @var (string)
	 */
	public    static $php_ver_min  = '5.5.30';

	/**
	 * Maximum php version.
	 *
	 * @var (string)
	 */
	public    static $php_ver_best = '5.6.15';

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
		self::$type     = __( 'File System', 'secupress' );
		self::$title    = __( 'Check if your installation is using a supported version of PHP.', 'secupress' );
		self::$more     = __( 'Every year old PHP version are not supported anymore, even for security patches so it\'s important to stay updated.', 'secupress' );
		$this->more_fix = static::get_messages( 300 );

		if ( false === ( $php_vers = get_site_transient( 'secupress_php_versions' ) ) ) {
			$response = wp_remote_get( 'http://php.net/releases/index.php?json&version=5&max=2' );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$php_vers = json_decode( wp_remote_retrieve_body( $response ) );
				$php_vers = array_keys( (array) $php_vers );
				set_site_transient( 'secupress_php_versions', $php_vers, 7 * DAY_IN_SECONDS );
			}
		}

		if ( $php_vers ) {
			list( self::$php_ver_best, self::$php_ver_min ) = $php_vers;
		}
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
			0   => sprintf( __( 'You are using <strong>PHP v%s</strong>.', 'secupress' ), phpversion() ),
			1   => sprintf( __( 'You are using <strong>PHP v%s</strong>, perfect!', 'secupress' ), phpversion() ),
			// "warning"
			100 => __( 'Unable to determine version of PHP.', 'secupress' ),
			// "bad"
			200   => sprintf( __( 'You are using <strong>PHP v%1$s</strong>, but the latest supported version is <strong>PHP v%2$s</strong>, and the best is <strong>PHP v%3$s</strong>.', 'secupress' ), phpversion(), self::$php_ver_min, self::$php_ver_best ),
			// "cantfix"
			300 => __( 'This cannot be automatically fixed. You have to contact you host provider to ask him to <strong>upgrade you version of PHP</strong>.', 'secupress' ),
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

		if ( version_compare( phpversion(), self::$php_ver_min ) < 0 ) {
			$this->add_message( 200 );
			$this->add_pre_fix_message( 300 );
		}

		// "good"
		if ( phpversion() === self::$php_ver_best ) {
			$this->add_message( 1 );
		} else {
			$this->maybe_set_status( 0 );
		}

		return parent::scan();
	}


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
}
