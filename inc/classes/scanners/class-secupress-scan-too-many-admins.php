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
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if there are more than three Administrators on this site.', 'secupress' );
		self::$more     = __( 'Accounts with Administrator privileges can perform any kind of action. The less Administrators you have, the lower the risk that any account has been compromised is.', 'secupress' );
		self::$more_fix = __( 'This will ask you to keep a maximum of 3 administrators on your website. You will have to choose between delete or downgrade some administrators.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => _n_noop( 'You have only <strong>%d Administrator</strong>, fine.', 'You have only <strong>%d Administrators</strong>, fine.', 'secupress' ),
			1   => _n( 'None of your sites have more than <strong>%d Administrator</strong>, fine.', 'None of your sites have more than <strong>%d Administrators</strong>, fine.', static::$max_admins, 'secupress' ),
			/* translators: 1 is a user name (or a list of user names), 2 is a user role. */
			2   => _n_noop( '%1$s successfully downgraded to %2$s.', '%1$s successfully downgraded to %2$s.', 'secupress' ),
			/* translators: %s is a user name (or a list of user names). */
			3   => __( 'User role successfully removed from %s.', 'secupress' ),
			/* translators: %s is a user name (or a list of user names). */
			4   => _n_noop( '%s successfully deleted.', '%s successfully deleted.', 'secupress' ),
			// warning
			100 => _n_noop( 'You still have <strong>%d Administrator</strong>.', 'You still have <strong>%d Administrators</strong>.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d Administrator</strong> found on this site.', '<strong>%d Administrators</strong> found on this site.', 'secupress' ),
			201 => _n_noop( 'More than %1$d Administrators found on the site %2$s.', 'More than %1$d Administrators found on the sites %2$s.', 'secupress' ),
			202 => __( 'Error: invalid data or no data sent.', 'secupress' ),
			203 => __( 'Please select a valid user.', 'secupress' ),
			204 => __( 'Please select a valid user role.', 'secupress' ),
			/* translators: 1 is a user name (or a list of user names), 2 is a user role. */
			205 => _n_noop( '%1$s could not be downgraded to %2$s. You should try to do it manually.', '%1$s could not be downgraded to %2$s. You should try to do it manually.', 'secupress' ),
			/* translators: %s is a user name (or a list of user names). */
			206 => __( 'User role could not be removed from %s.', 'secupress' ),
			/* translators: %s is a user name (or a list of user names). */
			207 => _n_noop( '%s could not be deleted. You should try to do it manually.', '%s could not be deleted. You should try to do it manually.', 'secupress' ),
			208 => __( 'Please select a valid user to whom attribute posts.', 'secupress' ),
			209 => __( 'Hey, I can\'t assign Posts to a user who will be deleted!', 'secupress' ),
			// cantfix
			300 => __( 'Please delete some users or change their role to get a maximum of %s Administrators.', 'secupress' ),
			/* translators: %s is the plugin name. */
			301 => sprintf( __( 'This cannot be fixed from here. A new %s menu item has been activated in the relevant site\'s administration area.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// MULTISITE ===============
		if ( $this->is_network_admin() ) {
			$this->scan_multisite();
			return parent::scan();
		}

		// MONOSITE ================
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

		return parent::scan();
	}


	public function fix() {

		// MONOSITE ================
		$count = count( get_users( array(
			'fields' => 'ids',
			'role'   => 'administrator',
		) ) );

		if ( $count > static::$max_admins ) {
			// bad
			$this->add_fix_message( 300, array( static::$max_admins ) );
			$this->add_fix_action( 'too-many-admins' );
		} else {
			// good
			$this->add_fix_message( 0, array( $count, $count ) );
		}

		return parent::fix();
	}


	public function manual_fix() {
		global $wpdb;

		if ( ! $this->has_fix_action_part( 'too-many-admins' ) ) {
			return parent::manual_fix();
		}

		// MONOSITE ================
		$what_to_do = ! empty( $_POST['secupress-fix-too-many-admins'] ) && is_array( $_POST['secupress-fix-too-many-admins'] ) ? $_POST['secupress-fix-too-many-admins'] : false;

		if ( ! $what_to_do ) {
			// bad: no valid data.
			$this->add_fix_message( 202 );
			$this->add_fix_action( 'too-many-admins' );
			return parent::manual_fix();
		}

		// Get selected Admins.
		$admins = ! empty( $what_to_do['admins'] ) ? $what_to_do['admins'] : false;
		$admins = static::sanitize_admins( $admins );

		if ( ! $admins ) {
			// bad: no Admins selected.
			$this->add_fix_message( 203 );
			$this->add_fix_action( 'too-many-admins' );
			return parent::manual_fix();
		}

		// What to do.
		$action = ! empty( $what_to_do['action'] ) ? $what_to_do['action'] : false;

		// Downgrade selected Admins.
		if ( $action === 'changerole' ) {
			$done = array();
			$fail = array();

			// Get selected role.
			$role = ! empty( $what_to_do['role'] ) ? $what_to_do['role'] : false;

			// Sanitize role only if "No role" is not selected.
			if ( $role !== 'norole' ) {
				$role_name = static::sanitize_user_role( $role );

				if ( ! $role_name ) {
					// bad: no role selected.
					$this->add_fix_message( 204 );
					$this->add_fix_action( 'too-many-admins' );
					return parent::manual_fix();
				}
			} else {
				$role = false;
			}

			// Change role.
			foreach ( $admins as $user_id ) {
				$user = get_userdata( $user_id );

				// No super powers anymore.
				$user->remove_role( 'administrator' );
				if ( $role ) {
					$user->add_role( $role );
				}

				if ( user_can( $user, 'administrator' ) || ( $role && ! user_can( $user, $role ) ) ) {
					$fail[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
				} else {
					$done[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
				}
			}

			if ( $done ) {
				// good
				if ( $role ) {
					$this->add_fix_message( 2, array( count( $done ), $done, $role_name ) );
				} else {
					$this->add_fix_message( 3, array( $done ) );
				}
			}

			if ( $fail ) {
				// bad
				if ( $role ) {
					$this->add_fix_message( 205, array( count( $fail ), $fail, $role_name ) );
				} else {
					$this->add_fix_message( 206, array( $fail ) );
				}
			}
		}
		// Delete selected Admins and delete/attribute posts.
		elseif ( $action === 'delete' ) {
			$posts_action = ! empty( $what_to_do['posts-action'] ) ? $what_to_do['posts-action'] : false;

			// Delete posts.
			if ( $posts_action === 'delete' ) {
				$done = array();
				$fail = array();

				foreach ( $admins as $user_id ) {
					$user = get_userdata( $user_id );

					if ( wp_delete_user( $user_id ) ) {
						$done[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
					} else {
						$fail[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
					}
				}

				if ( $done ) {
					// good
					$this->add_fix_message( 4, array( count( $done ), $done ) );
				}

				if ( $fail ) {
					// bad
					$this->add_fix_message( 207, array( count( $fail ), $fail ) );
				}
			}
			// Attribute posts to another user.
			elseif ( $posts_action === 'reassign' ) {
				$posts_user = ! empty( $what_to_do['posts-user'] ) ? $what_to_do['posts-user'] : false;
				$posts_user = static::sanitize_user_receiver( $posts_user );
				$done       = array();
				$fail       = array();

				if ( ! $posts_user ) {
					// bad: not a valid user.
					$this->add_fix_message( 208 );
					$this->add_fix_action( 'too-many-admins' );
					return parent::manual_fix();
				}

				if ( in_array( $posts_user, $admins ) ) {
					// bad: the chosen user will be deleted.
					$this->add_fix_message( 209 );
					$this->add_fix_action( 'too-many-admins' );
					return parent::manual_fix();
				}

				foreach ( $admins as $user_id ) {
					$user = get_userdata( $user_id );

					if ( wp_delete_user( $user_id, $posts_user ) ) {
						$done[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
					} else {
						$fail[] = '<strong>' . esc_html( $user->user_login ) . '</strong>';
					}
				}

				if ( $done ) {
					// good
					$this->add_fix_message( 4, array( count( $done ), $done ) );
				}

				if ( $fail ) {
					// bad
					$this->add_fix_message( 207, array( count( $fail ), $fail ) );
				}
			}
			// Uh?
			else {
				// bad: no valid data.
				$this->add_fix_message( 202 );
				$this->add_fix_action( 'too-many-admins' );
				return parent::manual_fix();
			}
		}
		// Uh?
		else {
			// bad: no valid data.
			$this->add_fix_message( 202 );
			$this->add_fix_action( 'too-many-admins' );
			return parent::manual_fix();
		}

		// Maybe we need another shot.
		$count = count( get_users( array(
			'fields' => 'ids',
			'role'   => 'administrator',
		) ) );

		if ( $count > static::$max_admins ) {
			// warning.
			$this->add_fix_message( 100, array( $count, $count ) );
			$this->add_fix_action( 'too-many-admins' );
		}

		return parent::manual_fix();
	}


	protected function get_fix_action_template_parts() {

		// MONOSITE ================
		$admins = static::get_admins( 'user_login' );

		if ( ! $admins ) {
			return array(
				'too-many-admins' => static::get_messages( 1 ),
			);
		}

		$base_id   = 'too-many-admins';
		$base_name = 'secupress-fix-too-many-admins';
		$roles     = wp_roles()->roles;
		unset( $roles['administrator'] );

		$dropdown = wp_dropdown_users( array(
			'name'     => $base_name . '[posts-user]',
			'id'       => $base_id . '-posts-user',
			'selected' => get_current_user_id(),
			'who'      => 'authors',
			'echo'     => 0,
		) );
		$has_authors = strpos( $dropdown, '<option value=' ) !== false;

		$form  = '<h4 id="secupress-fix-too-many-admins-title">' . __( 'Choose what to do:', 'secupress' ) . '</h4>';

		$form .= '<fieldset class="secupress-group-horizontal too-many-admins-field" aria-labbelledby="secupress-fix-too-many-admins-title">';

			$form .= '<input id="' . $base_id . '-action-changerole" type="radio" name=' . $base_name . '[action]" value="changerole" checked="checked" /> ';
			$form .= '<label id="' . $base_id . '-changerole-label" for="' . $base_id . '-action-changerole">' . __( 'Change role', 'secupress' ) . '</label>';
			$form .= '<input id="' . $base_id . '-action-delete" type="radio" name=' . $base_name . '[action]" value="delete" /> ';
			$form .= '<label id="' . $base_id . '-delete-label" for="' . $base_id . '-action-delete">' . __( 'Delete user', 'secupress' ) . '</label>';

			$form .= '<fieldset class="secupress-boxed-group secupress-checkbox-group-vertical too-many-admins-admins-wrapper" aria-labelledby="' . $base_id . '-legend">';
				$form .= '<legend id="' . $base_id . '-legend"><strong>' . __( 'Affected Administrators', 'secupress' ) . '</strong></legend>';
				$form .= '<ul>';
					foreach ( $admins as $admin ) {
						$admin->ID = absint( $admin->ID );
						$form .= '<li>';
							$form .= '<input id="' . $base_id . '-admin-' . $admin->ID . '" type="checkbox" name=' . $base_name . '[admins][]" value="' . $admin->ID . '" checked="checked" /> ';
							$form .= '<label for="' . $base_id . '-admin-' . $admin->ID . '">' . esc_html( $admin->display_name ) . ' <span class="description">(' . esc_html( $admin->user_login ) . ')</span></label>';
						$form .= '</li>';
					}
				$form .= '</ul>';
			$form .= '</fieldset>';

			$form .= '<fieldset class="secupress-group too-many-admins-role-wrapper" aria-labelledby="' . $base_id . '-role-label">';
				$form .= '<label for="' . $base_id . '-role" id="' . $base_id . '-role-label">' . __( 'Change role to&hellip;' ) . '</label> '; // WPi18n
				$form .= '<select id="' . $base_id . '-role" name="' . $base_name . '[role]">';
					$form .= '<option value="norole">' . __( '&mdash; No role for this site &mdash;' ) . '</option>'; // WPi18n

					if ( $roles ) {
						$default_role = static::get_default_role();

						foreach ( $roles as $role => $details ) {
							$form .= '<option' . ( $default_role === $role ? ' selected="selected"' : '' ) . ' value="' . esc_attr( $role ) . '">' . translate_user_role( $details['name'] ) . '</option>';
						}
					}

				$form .= '</select>';
			$form .= '</fieldset>';

			$form .= '<fieldset class="secupress-group secupress-radio-group-vertical too-many-admins-posts-wrapper">';
				$form .= '<p><legend>' . __( 'What should be done with content owned by this user?' ) . '</legend></p>'; // WPi18n
				$form .= '<ul>';
					$form .= '<li>';
						$form .= '<input type="radio" id="' . $base_id . '-posts-delete" name="' . $base_name . '[posts-action]" value="delete"' . ( $has_authors ? '' : ' checked="checked"' ) . ' /> <label for="' . $base_id . '-posts-delete">' . __( 'Delete all content.' ) . '</label>'; // WPi18n
					$form .= '</li>';

					if ( $has_authors ) {
						$form .= '<li>';
							$form .= '<input type="radio" id="' . $base_id . '-posts-reassign" name="' . $base_name . '[posts-action]" value="reassign" checked="checked" /> ';
							$form .= '<label for="' . $base_id . '-posts-reassign">' . __( 'Attribute all content to:' ) . '</label> '; // WPi18n
							$form .= $dropdown;
						$form .= '</li>';
					}

				$form .= '</ul>';
			$form .= '</fieldset>';

		$form .= '</fieldset>';

		return array( 'too-many-admins' => $form );
	}


	/*--------------------------------------------------------------------------------------------*/
	/* TOOLS FOR MONOSITE ======================================================================= */
	/*--------------------------------------------------------------------------------------------*/

	/*
	 * Return a list of Administrators, excluding the current Admin.
	 *
	 * @since 1.0
	 *
	 * @return (array) Array of WP_User objects.
	 */
	final protected static function get_admins() {
		return get_users( array(
			'role'    => 'administrator',
			'exclude' => array( get_current_user_id() ),
			'fields'  => array( 'ID', 'display_name', 'user_login' ),
		) );
	}


	/*
	 * Sanitize user IDs and make sure they are all Administrators.
	 * Current Administrator is excluded from the list.
	 *
	 * @since 1.0
	 *
	 * @param (array) $admins Array of user IDs.
	 *
	 * @return (array) Array of user IDs.
	 */
	final protected static function sanitize_admins( $admins ) {
		if ( ! $admins || ! is_array( $admins ) ) {
			return array();
		}

		$admins = array_filter( array_map( 'absint', $admins ) );

		if ( ! $admins ) {
			return array();
		}

		$admins     = array_unique( $admins );
		$all_admins = get_users( array(
			'role'    => 'administrator',
			'exclude' => array( get_current_user_id() ),
			'fields'  => 'ID',
		) );

		if ( ! $all_admins ) {
			// Nice try.
			return array();
		}

		$all_admins = array_map( 'absint', $all_admins );
		$admins     = array_intersect( $admins, $all_admins );

		if ( ! $admins ) {
			// Nice try.
			return array();
		}

		if ( count( $admins ) === count( $all_admins ) ) {
			/*
			 * Uh? Okay you're cheating, you're not an Admin.
			 * But I won't let you downgrade or delete all the Admins, I'll keep the oldest one secure.
			 */
			sort( $admins, SORT_NUMERIC );
			array_shift( $admins );
		}

		return array_values( $admins );
	}


	/*
	 * Sanitize a user role.
	 * Make sure the role exists and is not 'administrator'.
	 *
	 * @since 1.0
	 *
	 * @param (string) $role What do you think?
	 *
	 * @return (bool|string) Label of the role, false on failure.
	 */
	final protected static function sanitize_user_role( $role ) {
		if ( ! $role ) {
			return false;
		}

		$roles = wp_roles()->roles;
		unset( $roles['administrator'] );

		return isset( $roles[ $role ] ) ? translate_user_role( $roles[ $role ]['name'] ) : false;
	}


	/*
	 * Sanitize a user ID and make sure the role can create posts.
	 *
	 * @since 1.0
	 *
	 * @param (int) $user_id A user ID.
	 *
	 * @return (bool|int) User ID, false on failure.
	 */
	final protected static function sanitize_user_receiver( $user_id ) {
		$user_id = absint( $user_id );

		if ( ! $user_id ) {
			return false;
		}

		$users = get_users( array(
			'who'    => 'authors',
			'fields' => 'ID',
		) );

		if ( ! $users ) {
			return false;
		}

		$users = array_map( 'absint', $users );
		$users = array_flip( $users );
		return isset( $users[ $user_id ] ) ? $user_id : false;
	}


	/*--------------------------------------------------------------------------------------------*/
	/* MULTISITE ================================================================================ */
	/*--------------------------------------------------------------------------------------------*/

	protected function scan_multisite() {
		global $wpdb;

		$admins = static::get_usernames_per_blog();

		if ( $admins ) {
			$blog_names = array();

			foreach ( $admins as $site_id => $users ) {
				$table_prefix = $wpdb->get_blog_prefix( $site_id );
				$blog_name    = $wpdb->get_var( "SELECT option_value FROM {$table_prefix}options WHERE option_name = 'blogname' LIMIT 1" );
				$blog_names[] = '<strong>' . ( $blog_name ? esc_html( $blog_name ) : '(' . $site_id . ')' ) . '</strong>';
			}

			// bad
			$this->add_message( 201, array( count( $blog_names ), static::$max_admins, $blog_names ) );

			// Messages for sub-sites.
			$blogs = static::get_blog_ids();

			foreach ( $blogs as $site_id ) {
				$users = isset( $admins[ $site_id ] ) ? count( $admins[ $site_id ] ) : 0;

				if ( $users ) {
					// Add a scan message for each listed sub-site.
					$this->add_subsite_message( 200, array( $users, $users ), 'scan', $site_id );
				} else {
					$this->set_empty_data_for_subsite( $site_id );
				}
			}

			// cantfix
			$this->add_pre_fix_message( 301 );
		} else {
			// good
			$this->add_message( 1, array( static::$max_admins ) );
			// Remove all previously stored messages for sub-sites.
			$this->set_empty_data_for_subsites();
		}
	}


	/*--------------------------------------------------------------------------------------------*/
	/* TOOLS FOR MULTISITE ====================================================================== */
	/*--------------------------------------------------------------------------------------------*/

	/*
	 * Return a list of Administrators per blog like:
	 * array(
	 *     blog_id_1 => array(
	 *         user_id_1 => username_1,
	 *         user_id_2 => username_2,
	 *     ),
	 *     blog_id_2 => array(
	 *         user_id_1 => username_1,
	 *         user_id_2 => username_2,
	 *         user_id_3 => username_3,
	 *         user_id_4 => username_4,
	 *     ),
	 * )
	 *
	 * @return (array)
	 */
	final protected static function get_usernames_per_blog() {
		global $wpdb;
		$admins_per_blog = array();
		$user_logins     = array();

		$prefix  = secupress_esc_like( $wpdb->prefix );
		$results = $wpdb->get_results( "SELECT user_id, user_login, meta_key FROM $wpdb->usermeta AS um RIGHT JOIN $wpdb->users AS u ON um.user_id = u.ID WHERE meta_key LIKE '$prefix%capabilities' AND meta_value LIKE '%s:13:\"administrator\";b:1;%'" );

		if ( $results ) {
			// Fetch administrators.
			foreach ( $results as $result ) {
				$blog_id = preg_replace( "/^{$prefix}((?:\d+_|)*)capabilities$/", '$1', $result->meta_key );
				$blog_id = max( 1, (int) trim( $blog_id, '_' ) );
				$user_id = (int) $result->user_id;

				$user_logins[ $user_id ]     = isset( $user_logins[ $user_id ] ) ? $user_logins[ $user_id ] : esc_html( $result->user_login );
				$admins_per_blog[ $blog_id ] = isset( $admins_per_blog[ $blog_id ] ) ? $admins_per_blog[ $blog_id ] : array();
				$admins_per_blog[ $blog_id ][ $user_id ] = $user_logins[ $user_id ];
			}

			// Limit results to blogs with 4 administrators or more.
			foreach ( $admins_per_blog as $blog_id => $user_logins ) {
				if ( count( $user_logins ) <= static::$max_admins ) {
					unset( $admins_per_blog[ $blog_id ] );
				}
			}
		}

		return $admins_per_blog;
	}


	/*--------------------------------------------------------------------------------------------*/
	/* OTHER TOOLS ============================================================================== */
	/*--------------------------------------------------------------------------------------------*/

	/*
	 * Find the most appropriate role (the one with the largest number of capabilities, and able to publish Posts).
	 */
	final public static function get_default_role() {
		static $default_role;

		if ( ! isset( $default_role ) ) {
			$default_role = false;
			$nbr_caps     = 0;
			$roles        = wp_roles()->roles;
			unset( $roles['administrator'] );

			if ( $roles ) {
				foreach ( $roles as $role => $details ) {
					$role_nbr_caps = count( array_filter( $details['capabilities'] ) );

					if ( $role_nbr_caps > $nbr_caps ) {
						$default_role = $role;
						$nbr_caps     = $role_nbr_caps;
					}
				}
			}
		}

		return $default_role;
	}
}
