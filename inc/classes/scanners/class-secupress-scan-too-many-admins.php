<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Too Many Admins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Too_Many_Admins extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio       = 'medium';
	protected static $max_admins = 3;


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if there are more than three Administrators on this site.', 'secupress' );
		self::$more  = __( 'Accounts with Administrator privileges can perform any kind of action. The less Administrators you have, the lower the risk that any account has been compromised is.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => _n_noop( 'You have only <strong>%d Administrator</strong>, fine.', 'You have only <strong>%d Administrators</strong>, fine.', 'secupress' ),
			1   => __( 'None of your sites have more than <strong>%d Administrator</strong>, fine.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d Administrator</strong> found on this site.', '<strong>%d Administrators</strong> found on this site.', 'secupress' ),
			201 => _n_noop( 'More than %1$d Administrators found on the site %2$s.', 'More than %1$d Administrators found on the sites %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		if ( is_multisite() ) {
			$admins = static::get_admins_per_blog();

			if ( $admins ) {
				$blog_names = array();

				foreach ( $admins as $blog_id => $users ) {
					$table_prefix = $wpdb->get_blog_prefix( $blog_id );
					$blog_name    = $wpdb->get_var( "SELECT option_value FROM {$table_prefix}options WHERE option_name = 'blogname' LIMIT 1" );
					$blog_names[] = '<strong>' . ( $blog_name ? esc_html( $blog_name ) : '(' . $blog_id . ')' ) . '</strong>';
				}

				// bad
				$this->add_message( 201, array( count( $blog_names ), static::$max_admins, wp_sprintf_l( '%l', $blog_names ) ) );
			} else {
				// good
				$this->add_message( 1, array( static::$max_admins ) );
			}

		} else {

			$count = count( get_users( array(
				'fields' => 'ids',
				'role'   => 'administrator',
			) ) );

			if ( $count > static::$max_admins ) {
				// bad
				$this->add_message( 200, array( $count, $count ) );
			} else {
				// good
				$this->add_message( 0, array( $count, $count ) );
			}
		}

		return parent::scan();
	}


	public function fix() {

		// table usermeta. user_id
		// meta_key: wp_capabilities, wp_2_capabilities...
		// meta_value: s:13:"administrator";b:1;

		return parent::fix();
	}


	/*
	 * Return a list of admins per blog like:
	 * array(
	 *     blog_id_1 => array(
	 *         user_id_1 => user_id_1,
	 *         user_id_2 => user_id_2,
	 *         user_id_3 => user_id_3,
	 *         user_id_4 => user_id_4,
	 *     ),
	 *     blog_id_2 => array(
	 *         user_id_1 => user_id_1,
	 *         user_id_2 => user_id_2,
	 *         user_id_3 => user_id_3,
	 *         user_id_4 => user_id_4,
	 *         user_id_5 => user_id_5,
	 *     ),
	 * )
	 */
	final protected static function get_admins_per_blog() {
		global $wpdb;
		$admins_per_blog = array();

		$prefix  = $wpdb->esc_like( $wpdb->prefix );
		$results = $wpdb->get_results( "SELECT user_id, meta_key FROM $wpdb->usermeta AS um RIGHT JOIN $wpdb->users AS u ON um.user_id = u.ID WHERE meta_key LIKE '$prefix%capabilities' AND meta_value LIKE '%s:13:\"administrator\";b:1;%'" );

		if ( $results ) {
			// Fetch administrators.
			foreach ( $results as $result ) {
				$blog_id = preg_replace( "/^{$prefix}((?:\d+_|)*)capabilities$/", '$1', $result->meta_key );
				$blog_id = max( 1, (int) trim( $blog_id, '_' ) );
				$user_id = (int) $result->user_id;

				$admins_per_blog[ $blog_id ] = isset( $admins_per_blog[ $blog_id ] ) ? $admins_per_blog[ $blog_id ] : array();
				$admins_per_blog[ $blog_id ][ $user_id ] = $user_id;
			}

			// Limit results to blogs with 4 administrators or more.
			foreach ( $admins_per_blog as $blog_id => $user_ids ) {
				if ( count( $user_ids ) <= static::$max_admins ) {
					unset( $admins_per_blog[ $blog_id ] );
				}
			}
		}

		return $admins_per_blog;
	}
}
