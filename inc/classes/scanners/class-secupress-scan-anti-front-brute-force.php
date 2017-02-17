<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Anti Front Brute-Force scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Anti_Front_Brute_Force extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	protected $fixable = 'pro';


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your website is vulnerable to attacks by multiple and quick requests (DDoS like).', 'secupress' );
		$this->more     = __( 'Nobody needs to load more than 10 pages per second on your front-end, back-end or login page. You should block the requests\' owner.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the <strong>%1$s</strong> from the module %2$s.', 'secupress' ),
			__( 'Anti Front-End Brute-Force', 'secupress' ),
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bruteforce_activated">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
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
			0   => __( 'Your website seems to be protected against multiple and quick requests.', 'secupress' ),
			1   => __( 'The <strong>Anti Front-End Brute-Force</strong> module has been activated.', 'secupress' ),
			// "bad"
			200 => __( 'Your website is not protected from multiple and quick requests.', 'secupress' ),
			201 => sprintf( __( 'Our module %s could fix this.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bruteforce_activated">' . __( 'Anti Front-End Brute-Force', 'secupress' ) . '</a>' ),
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
		return __( 'http://docs.secupress.me/article/110-brute-force-attack-vulnerability-scan', 'secupress' );
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
		if ( ! secupress_is_submodule_active( 'firewall', 'bruteforce' ) ) {
			// "bad"
			$this->add_message( 200 );
			$this->add_pre_fix_message( 201 );
		}

		// "good"
		$this->maybe_set_status( 0 );

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
		secupress_activate_submodule( 'firewall', 'bruteforce' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
