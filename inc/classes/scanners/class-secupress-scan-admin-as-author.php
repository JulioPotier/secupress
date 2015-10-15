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
		self::$title = __( 'Check if any Administrator already created public posts.', 'secupress' );
		self::$more  = __( 'The <strong>Administrator</strong> role is to administrate the website, not to create posts, there are other roles for that, like <strong>Author</strong>. But mainly, it means that your Administrator account is always logged in, an attacker could then perform actions on your behalf (<abbr title="Cross-Site Request Forgery">CSRF</abbr> flaw).', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Perfect, no Posts created by Administrators.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%s</strong> Post has an <strong>Administrator</strong> as author.', '<strong>%s</strong> Posts have an <strong>Administrator</strong> as author.', 'secupress' ),
			201 => _n_noop( '%s has Posts created by Administrators.', 'Some of your sites have Posts created by Administrators: %s.', 'secupress' ),
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

				foreach ( $admins as $blog_id => $user_ids ) {
					$table_prefix = $wpdb->get_blog_prefix( $blog_id );
					$user_ids     = implode( ',', $user_ids );
					$nbr_posts    = $wpdb->get_var( "SELECT COUNT(ID) FROM {$table_prefix}posts WHERE post_author IN ($user_ids) AND post_type = 'post' LIMIT 1" );

					if ( $nbr_posts ) {
						$blog_name    = $wpdb->get_var( "SELECT option_value FROM {$table_prefix}options WHERE option_name = 'blogname' LIMIT 1" );
						$blog_names[] = '<strong>' . ( $blog_name ? esc_html( $blog_name ) : '(' . $blog_id . ')' ) . '</strong>';
					}
				}

				if ( $blog_names ) {
					// bad
					$this->add_message( 201, array( count( $blog_names ), wp_sprintf_l( '%l', $blog_names ) ) );
				} else {
					// good
					$this->add_message( 0 );
				}
			} else {
				// good
				$this->add_message( 0 );
			}

		} else {

			// Get posts created by an Administrator.
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
			} else {
				// good
				$this->add_message( 0 );
			}
		}

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}


	/*
	 * Return a list of admins per blog like:
	 * array(
	 *     blog_id_1 => array(
	 *         user_id_1 => user_id_1,
	 *         user_id_2 => user_id_2,
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
		}

		return $admins_per_blog;
	}
}
