<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Anti Front Bruteforce scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Anti_Front_Bruteforce extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	protected $fixable = 'pro';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your website can be attacked by multiple and quick requests (DDoS like).', 'secupress' );
		self::$more     = __( 'Nobody needs to load more than 10 pages per second on your front-end, back-end or login page. You should block the requests\' owner.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'This will activate the <strong>%1$s</strong> from the module %2$s.', 'secupress' ),
			__( 'Anti Front Bruteforce', 'secupress' ),
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
			0   => __( 'Your website seems to be protected by multiple and quick requests.', 'secupress' ),
			1   => __( 'The <strong>Anti Front Bruteforce</strong> module has been activated.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determinate status of your homepage.', 'secupress' ),
			// "bad"
			200 => __( 'Your website is not protected from multiple and quick requests.', 'secupress' ),
			201 => sprintf( __( 'Our module <a href="%s">%s</a> could fix this.', 'secupress' ), esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bruteforce_activated', __( 'Anti Front Bruteforce', 'secupress' ) ),
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
		if ( ! secupress_is_submodule_active( 'firewall', 'antibruteforcemanagement' ) ) {
			// "bad"
			$this->add_message( 200 );
			$this->add_pre_fix_message( 201 );
		}
		delete_site_transient( 'secupress_dont_ban_me_on_bruteforce' );

		// "good"
		$this->maybe_set_status( 200 );

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
		if ( secupress_is_pro() && function_exists( 'secupress_pro_fix_anti_front_bruteforce' ) ) {
			secupress_pro_fix_anti_front_bruteforce( $this );
			// "good"
			$this->add_fix_message( 1 );
		} else {
			// "bad"
			$this->add_fix_message( 201 );
		}

		return parent::fix();
	}
}
