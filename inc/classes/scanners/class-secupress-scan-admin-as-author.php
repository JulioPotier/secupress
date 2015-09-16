<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Admin As Author scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Admin_As_Author extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'low';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if any administrator already created a public post.', 'secupress' );
		self::$more  = __( 'The <em>administrator</em> role is to administrate the website, not creating posts, there is other roles for that. Also it means that your admin account is always logged in, this can easily lead to CSRF attacks.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Perfect, no posts created by admin.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%s</strong> post has an <strong>administrator</strong> as author.', '<strong>%s</strong> posts have an <strong>administrator</strong> as author.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$ids = get_posts( array(
			'fields'     => 'ids',
			'author__in' => get_users( array(
				'fields' => 'ids',
				'role'   => 'administrator',
			) ),
		) );

		$ids = count( $ids );

		if ( $ids ) {
			// bad
			$this->add_message( 200, array( $ids, number_format_i18n( $ids ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
