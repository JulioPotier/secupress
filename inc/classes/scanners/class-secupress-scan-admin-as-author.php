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
			1   => __( 'No Posts created by Administrators anymore.', 'secupress' ),
			2   => __( 'User role %s created.', 'secupress' ),
			3   => __( 'User role %1$s set to: %2$s.', 'secupress' ),
			// warning
			100 => __( '%s\'s user role still needs to be changed.', 'secupress' ),
			// bad
			200 => _n_noop( '%s is Administrator and a Post author at the same time.', '%s are Administrators and Post authors at the same time.', 'secupress' ),
			201 => _n_noop( '%s has Posts created by Administrators.', 'Some of your sites have Posts created by Administrators: %s.', 'secupress' ),
			202 => __( 'The new user role could not be created. You will need to create a user role able to publish Posts by yourself: some free plugins able to do that exist.', 'secupress' ),
			// cantfix
			300 => _n_noop( 'The user role of %d Administrator must be changed.', 'The user role of %d Administrators must be changed.', 'secupress' ),
			301 => __( 'It seems there are no user role, other than Administrator, able to create Posts. A new user role must be created.', 'secupress' ),
			302 => __( '%1$s created Posts with this account. A new Administrator account must be created: it is safer if you do it yourself. Once done, you can "downgrade" %1$s\'s user role; or come back here and I will do it for you.', 'secupress' ),
			303 => __( 'All Administrators created Posts. Obviously I can\'t "downgrade" all of them, at least one Administrator must be kept. A new Administrator account must be created first.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		// MULTISITE ===============
		if ( is_multisite() ) {
			$admins = static::get_posts_count_per_admin_per_blog();

			if ( $admins ) {
				$blog_names = array();

				foreach ( $admins as $blog_id => $users ) {
					$table_prefix = $wpdb->get_blog_prefix( $blog_id );
					$blog_name    = $wpdb->get_var( "SELECT option_value FROM {$table_prefix}options WHERE option_name = 'blogname' LIMIT 1" );
					$blog_names[] = '<strong>' . ( $blog_name ? esc_html( $blog_name ) : '(' . $blog_id . ')' ) . '</strong>';
				}

				// bad
				$this->add_message( 201, array( count( $blog_names ), wp_sprintf_l( '%l', $blog_names ), static::get_new_role( true ) ) );
			} else {
				// good
				$this->add_message( 0 );
			}

			return parent::scan();
		}

		// MONOSITE ================
		$admins = static::get_admins( 'user_login' );

		if ( $admins ) {
			// bad
			$this->add_message( 200, array( count( $admins ), wp_sprintf_l( '%l', static::wrap_in_tag( $admins, 'strong' ) ) ) );
		} else {
			// good
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	public function fix() {
		// MULTISITE ===============
		if ( is_multisite() ) {
			////
			return parent::fix();
		}

		// MONOSITE ================
		$admins = static::get_admins( 'user_login' );

		if ( ! $admins ) {
			// good
			$this->add_fix_message( 1 );
			return parent::fix();
		}

		$go_to_manual_fix = false;
		$new_role         = static::get_new_role( true );
		$count_admins     = count( $admins );

		// No suitable user role.
		if ( ! $new_role ) {
			// cantfix: create new role.
			$this->add_fix_message( 301 );
			$go_to_manual_fix = true;
		}

		$current_admin    = get_current_user_id();
		$all_admins       = get_users( array( 'role' => 'administrator' ) );
		$count_all_admins = count( $all_admins );

		// cantfix: admins must be downgraded.
		$this->add_fix_message( 300, array( $count_admins, $count_admins ) );

		if ( isset( $admins[ $current_admin ] ) ) {
			/*
			 * The current user is in the list.
			 */

			// cantfix: user must create a new admin account.
			$this->add_fix_message( 302, array( '<strong>' . $admins[ $current_admin ] . '</strong>' ) );

			if ( $count_admins > 1 ) {
				// cantfix: admins will be downgraded.
				$this->add_fix_message( 300, array( $count_admins, $count_admins ) ); // We include the current user in the list.
				$go_to_manual_fix = true;
			}

		} elseif ( count( $all_admins ) === $count_admins ) {
			/*
			 * All Administrators created Posts.
			 * Should not happen because current user is an Administrator.
			 * This is just for safety: someday we could use `manage_options` instead of `administrator` to be able to reach this settings page.
			 */

			// cantfix: we can't downgrade ALL Administrators.
			$this->add_fix_message( 303 );

		} else {
			/*
			 * The current user is not in the list.
			 */

			// cantfix: admins must be downgraded.
			$this->add_fix_message( 300, array( $count_admins, $count_admins ) );
			$go_to_manual_fix = true;
		}

		// Let's do it!
		if ( $go_to_manual_fix ) {
			$this->add_fix_action( 'admin-as-author' );
		}

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'admin-as-author' ) ) {
			return parent::manual_fix();
		}

		// MULTISITE ===============
		if ( is_multisite() ) {
			////
			return parent::manual_fix();
		}

		// MONOSITE ================
		$admins = static::get_admins();

		// No admins with Posts left.
		if ( ! $admins ) {
			// good
			$this->add_fix_message( 1 );
			return parent::manual_fix();
		}

		$new_role      = static::get_new_role();
		$new_role_name = static::get_new_role( true );
		$current_admin = get_current_user_id();
		$all_admins    = get_users( array( 'role' => 'administrator' ) );
		$warning       = false;

		// No suitable user role: create one.
		if ( ! $new_role ) {
			$new_role       = static::create_editor_role();
			$new_role_name  =_x( 'Post Author', 'User role' );

			if ( $new_role ) {
				// good: new user role created.
				$this->add_fix_message( 2, array( '<strong>' . $new_role_name . '</strong>' ) );
			} else {
				// bad: the user role could not be created.
				$this->add_fix_message( 202 );
				return parent::manual_fix();
			}
		}

		// Change Admins role.
		if ( isset( $admins[ $current_admin ] ) ) {
			/*
			 * The current user is in the list.
			 */
			$warning = '<strong>' . $admins[ $current_admin ]->user_login . '</strong>';
			unset( $admins[ $current_admin ] );

		} elseif ( count( $all_admins ) === count( $admins ) ) {
			/*
			 * All Administrators created Posts.
			 * Should not happen because current user is an Administrator.
			 * This is just for safety: someday we could use `manage_options` instead of `administrator` to be able to reach this settings page.
			 */

			// cantfix
			$this->add_fix_message( 303 );
			$admins = array();
		}

		if ( $admins ) {
			$done = array();

			foreach ( $admins as $admin ) {
				$admin->remove_role( 'administrator' );
				$admin->add_role( $new_role );
				$done[] = '<strong>' . $admin->user_login . '</strong>';
			}

			// good
			$this->add_fix_message( 3, array( '<strong>' . $new_role_name . '</strong>', wp_sprintf_l( '%l', $done ) ) );
		}

		if ( $warning ) {
			// warning
			$this->add_fix_message( 100, array( $warning ) );
		}

		$this->maybe_set_fix_status( 1 );

		return parent::manual_fix();
	}

	protected function get_fix_action_template_parts() {
		$parts = array();

		// MULTISITE ===============
		if ( is_multisite() ) {
			////
			$parts['admin-as-author'] = 'foo';
			return $parts;
		}

		// MONOSITE ================
		$admins = static::get_admins( 'user_login' );

		if ( $admins ) {
			// Tell the user what we will do.
			$out           = array();
			$todo          = array();
			$new_role      = static::get_new_role( true );
			$admins        = static::wrap_in_tag( $admins, 'strong' );
			$current_admin = get_current_user_id();
			$all_admins    = get_users( array( 'role' => 'administrator' ) );

			// No suitable user role.
			if ( ! $new_role ) {
				$new_role = _x( 'Post Author', 'User role' );
				$out[]    = static::get_messages( 301 );
				$todo[]   = __( 'A new user role will be created.', 'secupress' );
			}

			// Current user created Posts.
			if ( isset( $admins[ $current_admin ] ) ) {
				$out[] = static::get_messages( 302, array( '<strong>' . $admins[ $current_admin ] . '</strong>' ) );
				unset( $admins[ $current_admin ] );
			}

			// Downgrade users.
			if ( $admins ) {
				$count_admins = count( $admins );

				// Should not happen:
				if ( count( $all_admins ) === $count_admins ) {
					$out[]  = static::get_messages( 303 );
				}
				else {
					$out[]  = __( 'Some Administrators user role must be changed.', 'secupress' );
					$todo[] = sprintf( _n( '%1$s\'s user role will be changed to %2$s.', '%1$s\'s user role will be changed to %2$s.', $count_admins, 'secupress' ), wp_sprintf_l( '%l', $admins ), '<strong>' . $new_role . '</strong>' );
				}
			}

			if ( $todo ) {
				$out[] = '<strong>' . __( 'What will be done on next step:', 'secupress' ) . '</strong><ol><li>' . implode( '</li><li>', $todo ) . '</li></ol>';
			}

			$parts['admin-as-author'] = '<div class="speech-box">' . implode( '<br/><br/>', $out ) . '</div>';

		} else {
			// Meh.
			$parts['admin-as-author'] = static::get_messages( 1 );
		}

		return $parts;
	}


	/*
	 * Return a list of Administrators per blog + the number of their Posts like:
	 * array(
	 *     blog_id_1 => array(
	 *         user_id_1 => nbr_posts_of_user_1,
	 *         user_id_2 => nbr_posts_of_user_2,
	 *     ),
	 *     blog_id_2 => array(
	 *         user_id_1 => nbr_posts_of_user_1,
	 *         user_id_2 => nbr_posts_of_user_2,
	 *         user_id_3 => nbr_posts_of_user_3,
	 *         user_id_4 => nbr_posts_of_user_4,
	 *     ),
	 * )
	 * This is used for multisite.
	 */
	final protected static function get_posts_count_per_admin_per_blog() {
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

			// Limit results to administrators that have created Posts + count the number of Posts.
			foreach ( $admins_per_blog as $blog_id => $user_ids ) {
				$table_prefix = $wpdb->get_blog_prefix( $blog_id );
				$user_ids     = implode( ',', $user_ids );
				$user_ids     = $wpdb->get_results( "SELECT post_author, COUNT(ID) AS posts_count FROM {$table_prefix}posts WHERE post_author IN ($user_ids) AND post_type = 'post' AND post_status NOT IN ( 'trash', 'auto-draft' ) GROUP BY post_author" );

				if ( ! $user_ids ) {
					unset( $admins_per_blog[ $blog_id ] );
				} else {
					$admins_per_blog[ $blog_id ] = array();

					foreach ( $user_ids as $user ) {
						$admins_per_blog[ $blog_id ][ (int) $user->post_author ] = (int) $user->posts_count;
					}
				}
			}
		}

		return $admins_per_blog;
	}


	/*
	 * Return a list of Administrators that created Posts.
	 * This is used for non-multisite.
	 *
	 * @return (array) Array of WP_User objects.
	 */
	final protected static function get_admins( $field = false ) {
		$out   = array();
		$users = get_users( array( 'role' => 'administrator' ) );

		if ( $users ) {
			$tmp = array();
			foreach ( $users as $user ) {
				$user->ID = (int) $user->ID;
				$tmp[ $user->ID ] = $user;
			}
			$users = $tmp;

			$posts = get_posts( array(
				'author__in'  => array_keys( $users ),
				'post_status' => 'any',
			) );

			if ( $posts ) {
				foreach ( $posts as $post ) {
					$post->post_author = (int) $post->post_author;

					if ( ! isset( $out[ $post->post_author ] ) ) {
						$out[ $post->post_author ] = $field ? $users[ $post->post_author ]->$field : $users[ $post->post_author ];
					}
				}
			}
		}

		return $out;
	}


	/*
	 * Find the most appropriate role (the one with the largest number of capabilities, and able to publish Posts).
	 */
	final protected static function get_new_role( $translated = false ) {
		static $new_role;
		static $role_name;

		if ( ! isset( $new_role ) ) {
			$new_role  = false;
			$role_name = false;
			$nbr_caps  = 0;
			$cap       = post_type_exists( 'post' ) ? get_post_type_object( 'post' )->cap->publish_posts : 'publish_posts';
			$roles     = get_editable_roles();
			unset( $roles['administrator'] );

			if ( $roles ) {
				foreach ( $roles as $role => $details ) {
					$role_nbr_caps = count( array_filter( $details['capabilities'] ) );

					if ( $role_nbr_caps > $nbr_caps && ! empty( $details['capabilities'][ $cap ] ) ) {
						$new_role = $role;
						$nbr_caps = $role_nbr_caps;
					}
				}

				if ( $new_role ) {
					$role_name = translate_user_role( $roles[ $new_role ]['name'] );
				}
			}
		}

		return $translated ? $role_name : $new_role;
	}


	/*
	 * Create a role able to create Posts.
	 */
	final protected static function create_editor_role() {
		// Dummy gettext call to get strings in the catalog.
		/* translators: user role */
		_x( 'Editor', 'User role' ); // WPi18n
		$role      = 'editor';
		$role_name = 'Editor';

		if ( get_role( $role ) ) {
			/* translators: user role */
			_x( 'Post Author', 'User role' ); // Custom WPi18n
			$role      = 'postauthor';
			$role_name = 'Post Author';
		}

		$capabilities = array(
			'moderate_comments',
			'manage_categories',
			'manage_links',
			'upload_files',
			'unfiltered_html',
			'edit_posts',
			'edit_others_posts',
			'edit_published_posts',
			'publish_posts',
			'edit_pages',
			'read',
			'level_7',
			'level_6',
			'level_5',
			'level_4',
			'level_3',
			'level_2',
			'level_1',
			'level_0',
			'edit_others_pages',
			'edit_published_pages',
			'publish_pages',
			'delete_pages',
			'delete_others_pages',
			'delete_published_pages',
			'delete_posts',
			'delete_others_posts',
			'delete_published_posts',
			'delete_private_posts',
			'edit_private_posts',
			'read_private_posts',
			'delete_private_pages',
			'edit_private_pages',
			'read_private_pages',
		);

		add_role( $role, $role_name, $capabilities );

		return get_role( $role ) ? $role : false;
	}
}
