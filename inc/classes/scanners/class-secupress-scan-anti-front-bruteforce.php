<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Anti Front Bruteforce scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Anti_Front_Bruteforce extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio    = 'high';
	public    static $fixable = 'pro';


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your website can be attacked by multiple and quick requests (DDoS like).', 'secupress' );
		self::$more     = __( 'Noone needs to load more than 10 page per seconds on your front-end, back-end or login page. You should block the requests\' owner.', 'secupress' );
		self::$more_fix = sprintf(
			__( 'This will activate the <strong>%1$s</strong> from the module %2$s.', 'secupress' ),
			__( '', 'secupress' ),
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#antibruteforcemanagement">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your website seems to be protected by multiple and quick requests.', 'secupress' ),
			1   => __( 'The <strong>Anti Front Bruteforce</strong> module has been activated.', 'secupress' ),
			// warning
			100 => __( 'Unable to determinate status of your homepage.', 'secupress' ),
			// bad
			200 => __( 'Your website is not protected from multiple and quick requests.', 'secupress' ),
			201 => sprintf( __( 'Our module <a href="%s">%s</a> could fix this.', 'secupress' ), secupress_admin_url( 'modules', 'firewall#antibruteforcemanagement' ), __( 'Anti Front Bruteforce', 'secupress' ) ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		if ( ! secupress_is_submodule_active( 'firewall', 'antibruteforcemanagement' ) ) {
			// bad
			$this->add_message( 200 );
			$this->add_pre_fix_message( 201 );
		} 
		delete_site_transient( 'secupress_dont_ban_me_on_bruteforce' );

		// good
		$this->maybe_set_status( 200 ); // this 200 = our internal messsage

		return parent::scan();
	}


	public function fix() {

		if ( secupress_is_pro() && function_exists( 'secupress_pro_fix_anti_front_bruteforce' ) ) {
			secupress_pro_fix_anti_front_bruteforce();
		}

		return parent::fix();
	}
}
