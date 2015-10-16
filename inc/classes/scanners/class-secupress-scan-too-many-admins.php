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
			300 => __( 'Please delete some users or change their role to get a maximum of %s Administrators.', 'secupress' ),
			301 => __( 'Please delete some users or change their role to get a maximum of %s Administrators per blog.', 'secupress' ),
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

		if ( is_multisite() ) {
			$admins = static::get_admins_per_blog();

			if ( $admins ) {
				// cantfix
				$this->add_fix_message( 301, array( static::$max_admins ) );
				$this->add_fix_action( 'too-many-admins' );
			} else {
				// good
				$this->add_fix_message( 1, array( static::$max_admins ) );
			}

		} else {

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
		}

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'too-many-admins' ) ) {
			return parent::manual_fix();
		}

		// include the fix here.

		return parent::manual_fix();
	}


	public function get_fix_action_template_parts() {
		$form    = '';
		$blog_id = get_current_blog_id();
		$users   = get_users( array(
			'role' => 'administrator',
		) );

		if ( $users ) {
			$form .= '<div class="show-input">';
				$form .= '<h4 id="secupress-fix-too-many-admins-title">' . __( 'Choose what to do for each Administrator:', 'secupress' ) . '</h4>';
				$form .= '<div class="secupress-scrollable" aria-labelledby="secupress-fix-too-many-admins-title">';
					foreach ( $users as $user ) {
						$form .= static::user_row( $blog_id, $user );
					}
				$form .= '</div>';
			$form .= '</div>';
		}

		return array( 'too-many-admins' => $form );
	}


	protected static function user_row( $blog_id, $user ) {
		static $role_selector;

		if ( get_current_user_id() === $user->ID ) {
			return '';
		}

		$base_id   = 'too-many-admins-' . $blog_id . '-' . $user->ID;
		$base_name = 'secupress-fix-too-many-admins[' . $blog_id . '][' . $user->ID . ']';

		// Find the most appropriate role (the one with the largest number of capabilities).
		if ( ! isset( $role_selector ) ) {
			$new_role = '';
			$nbr_caps = 0;
			$roles    = get_editable_roles();
			unset( $roles['administrator'] );

			$role_selector  = '<label for="%base_id%-role">' . __( 'Change role to&hellip;' ) . '</label> '; // WPi18n
			$role_selector .= '<select id="%base_id%-role" name="%base_name%[role]">';
			$role_selector .= '<option value="">' . __( '&mdash; No role for this site &mdash;' ) . '</option>'; // WPi18n

			if ( $roles ) {
				foreach ( $roles as $role => $details ) {
					$role_nbr_caps = count( array_filter( $details['capabilities'] ) );

					if ( $role_nbr_caps > $nbr_caps ) {
						$new_role = $role;
						$nbr_caps = $role_nbr_caps;
					}
				}

				foreach ( $roles as $role => $details ) {
					$role_name      = translate_user_role( $details['name'] );
					$role_selector .= '<option' . ( $new_role === $role ? ' selected="selected"' : '' ) . ' value="' . esc_attr( $role ) . '">' . $role_name . '</option>';
				}

				$role_selector .= '</select>';
			}
		}

		$row  = '<fieldset class="secupress-boxed-group too-many-admins-field" aria-labbelledby="' . $base_id . '-legend">';
			$row .= '<legend id="' . $base_id . '-legend"><strong>' . $user->display_name . '</strong> <span class="description">(' . $user->user_login . ')</span></legend>';
			$row .= '<input id="' . $base_id . '-action" type="radio" name=' . $base_name . '[action]" value="" /> ';
			$row .= '<label id="' . $base_id . '-label" for="' . $base_id . '-action">' . __( 'Nothing', 'secupress' ) . '</label>';
			$row .= '<input id="' . $base_id . '-action-delete" type="radio" name=' . $base_name . '[action]" value="delete" /> ';
			$row .= '<label id="' . $base_id . '-delete-label" for="' . $base_id . '-action-delete">' . __( 'Delete user', 'secupress' ) . '</label>';
			$row .= '<input id="' . $base_id . '-action-changerole" type="radio" name=' . $base_name . '[action]" value="changerole" checked="checked" /> ';
			$row .= '<label id="' . $base_id . '-changerole-label" for="' . $base_id . '-action-changerole">' . __( 'Change role', 'secupress' ) . '</label>';

			$row .= '<fieldset class="too-many-admins-posts-wrapper">';
				$row .= '<p><legend>' . __( 'What should be done with content owned by this user?' ) . '</legend></p>'; // WPi18n
				$row .= '<ul>';
					$row .= '<li>';
						$row .= '<input type="radio" id="' . $base_id . '-posts-delete" name="' . $base_name . '[posts]" value="delete" /> <label for="' . $base_id . '-posts-delete">' . __( 'Delete all content.' ) . '</label>'; // WPi18n
					$row .= '</li>';
					$row .= '<li>';
						$row .= '<input type="radio" id="' . $base_id . '-posts-reassign" name="' . $base_name . '[posts]" value="reassign" /> ';
						$row .= '<label for="' . $base_id . '-posts-reassign">' . __( 'Attribute all content to:' ) . '</label> '; // WPi18n
						$row .= wp_dropdown_users( array(
							'name'    => $base_name . '[posts-user]',
							'id'      => $base_id . '-posts-user',
							'blog_id' => $blog_id,
							'who'     => 'authors',
							'exclude' => array( $user->ID ),
							'echo'    => 0,
						) );
					$row .= '</li>';
				$row .= '</ul>';
			$row .= '</fieldset>';

			$row .= '<fieldset class="too-many-admins-role-wrapper">' . str_replace( array( '%base_id%', '%base_name%', ), array( $base_id, $base_name, ), $role_selector ) . '</fieldset>';
		$row .= '</fieldset>';

		return $row;
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
