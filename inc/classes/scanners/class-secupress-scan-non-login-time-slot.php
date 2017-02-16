<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Non Login Time Slot scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Non_Login_Time_Slot extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		$this->title    = __( 'Check if your back-end is accessible 24h/24.', 'secupress' );
		$this->more     = __( 'You don\'t necessarily need to let your back-end open like 24 hours a day, you should close it during your sleeping time.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Non Login Time Slot', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-login-protection_type">' . __( 'Users & Login', 'secupress' ) . '</a>'
		);

		$timings = secupress_get_module_option( 'login-protection_nonlogintimeslot', false, 'users-login' );

		if ( $timings && is_array( $timings ) ) {
			$from = date_i18n( __( 'g:i a' ), mktime( $timings['from_hour'], $timings['from_minute'] ) );
			$to   = date_i18n( __( 'g:i a' ), mktime( $timings['to_hour'], $timings['to_minute'] ) );
			/** Translators: 1 and 2 are hours. */
			$this->more_fix .= '<br/>' . sprintf( __( 'Prevent anyone to log in from %1$s to %2$s <em>(this time slot can be changed in the module settings)</em>.', 'secupress' ), "<strong>$from</strong>", "<strong>$to</strong>" );

			if ( secupress_in_timeslot() ) {
				$this->more_fix .= '<br/><strong>' . __( 'If you do it right now you will be kicked out!', 'secupress' ) . '</strong>';
			}
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
			0   => __( 'You are currently <strong>locking</strong> your back-end, sometimes.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// "bad"
			200 => __( 'Your website should be <strong>locked out sometimes</strong>.', 'secupress' ),
			201 => sprintf( __( 'Our module %s could fix this.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-login-protection_type">' . __( 'Non Login Time Slot', 'secupress' ) ) . '</a>',
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
		return __( 'http://docs.secupress.me/article/130-restricted-admin-access-scan', 'secupress' );
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
		if ( ! secupress_is_submodule_active( 'users-login', 'nonlogintimeslot' ) ) {
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
		secupress_activate_submodule( 'users-login', 'nonlogintimeslot' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
