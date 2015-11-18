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
		self::$more  = __( 'The <strong>Administrator</strong> role is to fully manage the website but not to create posts. There are other roles for that like <strong>Editor</strong> or <strong>Author</strong>. But mainly, it means that your Administrator account is always logged in. An attacker could then perform actions on your behalf (<abbr title="Cross-Site Request Forgery">CSRF</abbr> flaw).', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'No Posts were created by Administrators.', 'secupress' ),
			1   => __( 'There is no more Posts created by Administrators.', 'secupress' ),
			/* translators: %s is a user role. */
			2   => __( 'User role %s created.', 'secupress' ),
			/* translators: %s is a user name. */
			3   => __( 'All your Posts have been attributed to %s.', 'secupress' ),
			/* translators: 1 is a user name, 2 is a user role. */
			4   => _n_noop( '%1$s successfully downgraded to %2$s.', '%1$s successfully downgraded to %2$s.', 'secupress' ),
			/* translators: %s is a logout link. */
			5   => sprintf( __( 'New <strong>Administrator</strong> account created. The current account will be downgraded as soon as you log into your new account (you should receive an e-mail very soon). %s?', 'secupress' ), '<a href="' . esc_url( wp_logout_url() ) . '">' . __( 'Logout' ) . '</a>' ), // WPi18n
			/* translators: %s is a user role. */
			6   => __( 'New %s account created.', 'secupress' ),
			// warning
			/* translators: %s is a user name. */
			100 => __( '%s\'s user role still needs to be changed.', 'secupress' ),
			// bad
			/* translators: %s is a user name. */
			200 => _n_noop( '%s is Administrator and a Post Author at the same time.', '%s are Administrators and Post Authors at the same time.', 'secupress' ),
			/* translators: %s is a site name (or a list of site names). */
			201 => _n_noop( '%s has Posts created by Administrators.', 'Some of your sites have Posts created by Administrators: %s.', 'secupress' ),
			202 => __( 'The new user role could not be created. You will need to create a user role able to publish Posts by yourself: some free plugins able to do such thing exist.', 'secupress' ),
			203 => __( 'Error: no data sent concerning your current user account.', 'secupress' ),
			204 => __( 'Please select a valid user to whom to attribute your Posts.', 'secupress' ),
			/* translators: 1 is a user name (or a list of user names), 2 is a user role. */
			205 => _n_noop( '%1$s could not be downgraded to %2$s. You should try to do it manually.', '%1$s could not be downgraded to %2$s. You should try to do it manually.', 'secupress' ),
			206 => __( 'Please provide data for your new user account.', 'secupress' ),
			207 => __( 'Please provide valid login and e-mail for your new user account.', 'secupress' ),
			208 => __( 'Sorry, that username already exists!' ), // WPi18n
			209 => __( 'Sorry, that username is not allowed.', 'secupress' ),
			210 => sprintf( __( 'Sorry, that username is invalid. It may not be longer than 60 characters and may contain only the following characters: %s', 'secupress' ), static::allowed_characters_for_login( true ) ),
			211 => __( 'Sorry, that email address is already used!' ), // WPi18n
			212 => __( 'Posts could not be attributed.', 'secupress' ),
			213 => __( 'Downgrading all Administrators is forbidden.', 'secupress' ),
			// cantfix
			300 => __( 'You created Posts with this account. A new account may be needed.', 'secupress' ),
			/* translators: %d is the number of Administrators. */
			301 => _n_noop( 'The user role of %d Administrator must be changed.', 'The user role of %d Administrators must be changed.', 'secupress' ),
			/* translators: %s is a user role. */
			302 => __( 'You chose to create a new %s account.', 'secupress' ),
			/* translators: %s is the plugin name. */
			303 => sprintf( __( 'This cannot be fixed from here. A new %s menu item has been activated in the relevant site\'s administration area.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
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
		$admins = static::get_admins( 'user_login' );

		if ( $admins ) {
			// bad
			$this->add_message( 200, array( count( $admins ), static::wrap_in_tag( $admins, 'strong' ) ) );
		} else {
			// good
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	/*
	 * Fixes:
	 * - Well, we fix nothing here actually. We only throw messages and display a form or informative text.
	 */
	public function fix() {

		// MULTISITE ===============
		if ( $this->is_network_admin() ) {
			$this->fix_network();
			return parent::fix();
		}

		// MONOSITE ================
		$admins       = static::get_admins( 'user_login' );
		$count_admins = count( $admins );

		if ( ! $count_admins ) {
			// good
			$this->add_fix_message( 1 );
			return parent::fix();
		}

		$current_admin           = get_current_user_id();
		$current_admin_is_author = isset( $admins[ $current_admin ] );
		$has_other_admin_authors = ! $current_admin_is_author || ( $current_admin_is_author && $count_admins > 1 );

		/*
		 * The current user is in the list.
		 */
		if ( $current_admin_is_author ) {
			--$count_admins;
			// cantfix: current user must create a new account.
			$this->add_fix_message( 300 );
		}

		/*
		 * Some other administrators created Posts.
		 */
		if ( $has_other_admin_authors ) {
			// cantfix: some admins must be downgraded.
			$this->add_fix_message( 301, array( $count_admins, $count_admins ) );
		}

		// Let's do it!
		$this->add_fix_action( 'admin-as-author' );

		return parent::fix();
	}


	/*
	 * Manual fixes.
	 */
	public function manual_fix() {

		// MULTISITE ===============
		if ( $this->is_network_admin() ) {
			$this->fix_network();
			return parent::manual_fix();
		}

		// MONOSITE ================
		if ( $this->has_fix_action_part( 'admin-as-author' ) ) {
			// Maybe create new role + maybe assign Posts + maybe downgrade Administrators.
			$this->manual_fix_main_action();
		}
		elseif ( $this->has_fix_action_part( 'admin-as-author-new-administrator' ) ) {
			// Create new Administrator account.
			$this->manual_fix_new_administrator_action();
		}
		elseif ( $this->has_fix_action_part( 'admin-as-author-new-editor' ) ) {
			// Create new Editor account.
			$this->manual_fix_new_editor_action();
		}

		return parent::manual_fix();
	}


	/*
	 * Individual fix:
	 * - Maybe create new role.
	 * - Maybe assign Posts.
	 * - Maybe downgrade Administrators.
	 */
	protected function manual_fix_main_action() {
		$admins       = static::get_admins( 'user_login' );
		$count_admins = count( $admins );

		// No admins with Posts left.
		if ( ! $count_admins ) {
			// good
			return $this->add_fix_message( 1 );
		}

		$final_test    = true;
		$current_admin = get_current_user_id();
		$new_role      = static::get_new_role();
		$new_role_name = '<strong>' . static::get_new_role( true ) . '</strong>';

		$current_admin_is_author = isset( $admins[ $current_admin ] );
		$has_other_admin_authors = ! $current_admin_is_author || ( $current_admin_is_author && $count_admins > 1 );

		/*
		 * No suitable user role: create one.
		 */
		if ( ! $new_role ) {
			$new_role = static::create_editor_role();

			if ( ! $new_role ) {
				// bad: the user role could not be created.
				return $this->add_fix_message( 202 );
			}

			$new_role_name = '<strong>' . $new_role['label'] . '</strong>';
			$new_role      = $new_role['name'];

			// good: new user role created.
			$this->add_fix_message( 2, array( $new_role_name ) );
		}

		/*
		 * The current user is in the list.
		 */
		if ( $current_admin_is_author ) {
			$what_to_do = ! empty( $_POST['secupress-fix-current-admin-as-author'] ) ? $_POST['secupress-fix-current-admin-as-author'] : false;

			// Create new Admin account.
			if ( $what_to_do === 'new-admin' ) {
				// cantfix: display a new form.
				$this->add_fix_message( 302, array( '<strong>' . _x( 'Administrator', 'User role' ) . '</strong>' ) );
				$this->add_fix_action( 'admin-as-author-new-administrator' );
				// Don't do the final test yet, or the message 100 (and all other messages) will be shown in the popup.
				$final_test = false;
			}
			// Assign Posts to an Editor.
			elseif ( $what_to_do === 'editor' ) {
				$editor_id = ! empty( $_POST['secupress-fix-current-admin-as-author-editor-choose'] ) ? (int) $_POST['secupress-fix-current-admin-as-author-editor-choose'] : 0;

				// Create new Editor account.
				if ( $editor_id === -1 ) {
					// cantfix: display a new form.
					$this->add_fix_message( 302, array( $new_role_name ) );
					$this->add_fix_action( 'admin-as-author-new-editor' );
					// Don't do the final test yet, or the message 100 (and all other messages) will be shown in the popup.
					$final_test = false;
				}
				// Use an existing Editor.
				else {
					if ( ! $editor_id || ! static::validate_editor( $editor_id ) || ! $this->attribute_posts_to( $editor_id ) ) {
						// bad: no user selected or user not valid (or I couldn't attribute Posts to him/her).
						$this->add_fix_message( 204 );
						$this->add_fix_action( 'admin-as-author' );
					}
				}
			}
			// Uh?
			else {
				// bad: I don't know what to do with the current user.
				$this->add_fix_message( 203 );
				$this->add_fix_action( 'admin-as-author' );
			}

			unset( $admins[ $current_admin ] );
			--$count_admins;
		}

		/*
		 * Some other administrators created Posts: downgrade them.
		 */
		if ( $has_other_admin_authors ) {

			if ( ! current_user_can( 'administrator' ) ) {
				// Not an Admin uh? I got a surprise for you.
				$all_admins = get_users( array(
					'role'    => 'administrator',
					'fields'  => 'ID',
				) );
				$all_admins = array_map( 'absint', $all_admins );

				if ( count( $admins ) === count( $all_admins ) ) {
					/*
					 * I won't let you downgrade all the Admins, I'll keep the oldest one secure.
					 */
					sort( $admins, SORT_NUMERIC );
					array_shift( $admins );
					// bad
					$this->add_message( 213 );
				}
			}

			if ( $admins ) {
				$done = array();
				$fail = array();

				foreach ( $admins as $user_id => $user_login ) {
					$user = get_userdata( $user_id );

					// No super powers anymore.
					$user->remove_role( 'administrator' );
					$user->add_role( $new_role );

					if ( user_can( $user, 'administrator' ) || ! user_can( $user, $new_role ) ) {
						$fail[] = '<strong>' . $user_login . '</strong>';
					} else {
						$done[] = '<strong>' . $user_login . '</strong>';
					}
				}

				if ( $done ) {
					// good
					$this->add_fix_message( 4, array( count( $done ), $done, $new_role_name ) );
				}

				if ( $fail ) {
					// bad
					$this->add_fix_message( 205, array( count( $fail ), $fail, $new_role_name ) );
				}
			}
		}

		// Final test
		if ( $final_test ) {
			$this->final_test();
		}
	}


	/*
	 * Individual fix:
	 * - Create new Admin account.
	 * - Set a transient to downgrade the current user account later.
	 */
	protected function manual_fix_new_administrator_action() {
		$data = ! empty( $_POST['secupress-fix-current-admin-as-author-new-administrator'] ) ? $_POST['secupress-fix-current-admin-as-author-new-administrator'] : false;

		if ( ! $data || ! is_array( $data ) ) {
			// bad
			$this->add_fix_message( 206 );
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-administrator' );
			return;
		}

		$login = ! empty( $data['login'] ) ? $data['login'] : false; // login will be sanitized in `wp_insert_user()`.
		$email = ! empty( $data['email'] ) ? sanitize_email( $data['email'] ) : false;

		if ( ! $login || ! $email ) {
			// bad
			$this->add_fix_message( 207 );
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-administrator' );
			return;
		}

		// A new super hero rises.
		$user_id = wp_insert_user( array(
			'user_login' => $login,
			'user_email' => $email,
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'administrator',
		) );

		// Well... Not that super in the end.
		if ( is_wp_error( $user_id ) ) {
			$error_code     = $user_id->get_error_code();
			$error_msg      = $user_id->get_error_message( $error_code );
			$illegal_compat = $error_code === 'empty_user_login' && $error_msg === __( 'Sorry, that username is not allowed.', 'secupress' );

			if ( $error_code === 'existing_user_login' ) {
				// bad
				$this->add_fix_message( 208 );
			} elseif ( $error_code === 'illegal_user_login' || $illegal_compat ) {
				// bad
				$this->add_fix_message( 209 );
			} elseif ( strpos( $error_code, 'user_login' ) !== false ) {
				// bad
				$this->add_fix_message( 210 );
			} elseif ( $error_code === 'existing_user_email' ) {
				// bad
				$this->add_fix_message( 211 );
			} else {
				// bad
				$this->add_fix_message( 207 );
			}
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-administrator' );
		} else {
			// good
			$this->add_fix_message( 5 );

			// Next time the new Administrator logs in, this current account will be downgraded.
			secupress_set_site_transient( 'secupress-admin-as-author-administrator', $user_id . '|' . get_current_user_id() );

			$user = get_userdata( $user_id );

			// Send notification by email.
			static::new_user_notification( $user );
		}
	}


	/*
	 * Individual fix:
	 * - Create new Editor account.
	 * - Assign Posts to it.
	 */
	protected function manual_fix_new_editor_action() {
		$data = ! empty( $_POST['secupress-fix-current-admin-as-author-new-editor'] ) ? $_POST['secupress-fix-current-admin-as-author-new-editor'] : false;

		if ( ! $data || ! is_array( $data ) ) {
			// bad
			$this->add_fix_message( 206 );
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-editor' );
			return;
		}

		$login = ! empty( $data['login'] ) ? $data['login'] : false; // login will be sanitized in `wp_insert_user()`.
		$email = ! empty( $data['email'] ) ? sanitize_email( $data['email'] ) : false;

		if ( ! $login || ! $email ) {
			// bad
			$this->add_fix_message( 207 );
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-editor' );
			return;
		}

		// We need a role first.
		$role      = static::get_new_role();
		$role_name = static::get_new_role( true );

		/*
		 * No suitable user role: create one (who the fuck deleted it?!).
		 */
		if ( ! $role ) {
			$role = static::create_editor_role();

			if ( ! $role ) {
				// bad: the user role could not be created.
				return $this->add_fix_message( 202 );
			}

			$role_name = $role['label'];
			$role      = $role['name'];
		}

		// Create the new Editor, with the same metas than the current user (well, not ALL metas, only the main ones).
		$metas = get_user_meta( get_current_user_id() );
		$metas = array_map( 'reset', $metas );
		unset( $metas['user_nicename'] );

		// A new citizen comes in town :)
		$user_id = wp_insert_user( array_merge( $metas, array(
			'user_login' => $login,
			'user_email' => $email,
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $role,
		) ) );

		// Oh, (s)he missed his/her highway exit.
		if ( ! $user_id || is_wp_error( $user_id ) ) {
			$error_code     = $user_id->get_error_code();
			$error_msg      = $user_id->get_error_message( $error_code );
			$illegal_compat = $error_code === 'empty_user_login' && $error_msg === __( 'Sorry, that username is not allowed.', 'secupress' );

			if ( $error_code === 'existing_user_login' ) {
				// bad
				$this->add_fix_message( 208 );
			} elseif ( $error_code === 'illegal_user_login' || $illegal_compat ) {
				// bad
				$this->add_fix_message( 209 );
			} elseif ( strpos( $error_code, 'user_login' ) !== false ) {
				// bad
				$this->add_fix_message( 210 );
			} elseif ( $error_code === 'existing_user_email' ) {
				// bad
				$this->add_fix_message( 211 );
			} else {
				// bad
				$this->add_fix_message( 207 );
			}
			// Get the form back.
			$this->add_fix_action( 'admin-as-author-new-editor' );
		} else {
			// good
			$this->add_fix_message( 6, array( '<strong>' . $role_name . '</strong>' ) );

			$user = get_userdata( $user_id );

			// Send notification by email.
			static::new_user_notification( $user );

			// Assign Posts.
			if ( ! $this->attribute_posts_to( $user ) ) {
				// bad: Posts could not be assigned.
				$this->add_fix_message( 212 );
			}

			// Final test.
			$this->final_test();
		}
	}


	/*
	 * Template parts.
	 */
	protected function get_fix_action_template_parts() {

		// MULTISITE ===============
		if ( $this->is_network_admin() ) {
			return array(
				'admin-as-author'                   => static::get_messages( 303 ),
				'admin-as-author-new-editor'        => static::get_messages( 303 ),
				'admin-as-author-new-administrator' => static::get_messages( 303 ),
			);
		}

		// MONOSITE ================
		$admins = static::get_admins( 'user_login' );

		if ( ! $admins ) {
			return array(
				'admin-as-author'                   => static::get_messages( 1 ),
				'admin-as-author-new-administrator' => static::get_messages( 1 ),
				'admin-as-author-new-editor'        => static::get_messages( 1 ),
			);
		}

		$current_admin       = get_current_user_id();
		$current_admin_login = get_userdata( $current_admin )->user_login;
		$current_admin_login = sanitize_user( $current_admin_login, true );
		$role_name           = static::get_new_role( true );
		$needs_new_role      = ! $role_name;

		if ( $needs_new_role ) {
			$role_name = get_role( 'editor' ) ? _x( 'Post Author', 'User role' ) : _x( 'Editor', 'User role' ); // WPi18n
		}

		return array(
			// STEP 1: ASK WHAT TO DO.
			'admin-as-author'                   => static::get_fix_main_action_template_part( $admins, $current_admin, $role_name, $needs_new_role ),
			// STEP 2: CREATE NEW ADMINISTRATOR ACCOUNT.
			'admin-as-author-new-administrator' => static::get_fix_new_administrator_action_template_part( $current_admin_login ),
			// STEP 2bis: CREATE NEW EDITOR ACCOUNT.
			'admin-as-author-new-editor'        => static::get_fix_new_editor_action_template_part( $current_admin_login, $role_name ),
		);
	}


	/*
	 * Template part for step 1:
	 * - Ask what to do.
	 */
	protected static function get_fix_main_action_template_part( $admins, $current_admin, $role_name, $needs_new_role ) {
		$count_admins   = count( $admins );
		$form           = '';
		$star1          = '<sup class="more-info" title="' . esc_attr__( 'More Info', 'secupress' ) . '">(1)</sup>';
		$star2          = '<sup class="more-info" title="' . esc_attr__( 'More Info', 'secupress' ) . '">(2)</sup>';
		$role_name      = '<strong>' . $role_name . '</strong>';
		$role_name_star = $role_name . ( $needs_new_role ? $star2 : '' );

		$current_admin_is_author = isset( $admins[ $current_admin ] );
		$has_other_admin_authors = ! $current_admin_is_author || ( $current_admin_is_author && $count_admins > 1 );


		/*
		 * The current user is in the list.
		 */
		if ( $current_admin_is_author ) {
			unset( $admins[ $current_admin ] );
			--$count_admins;

			$form .= '<h4 id="secupress-fix-current-admin-as-author">' . __( 'You created Posts with this account, what should I do?', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-current-admin-as-author" class="secupress-group">';
				$form .= '<ul class="secupress-radio-group-vertical">';

					// Create new Admin account.
					$form .= '<li>';
						$form .= '<input type="radio" checked="checked" name="secupress-fix-current-admin-as-author" id="secupress-fix-current-admin-as-author_new-admin" value="new-admin" /> ';

						$form .= '<label for="secupress-fix-current-admin-as-author_new-admin">';
							/* translators: %s is a user role name. */
							$form .= sprintf( __( 'Create a new <strong>Administrator</strong> account and downgrade this account to %s.', 'secupress' ), $role_name_star );
						$form .= '</label>';
					$form .= '</li>';

					// Assign Posts to an Editor/Author.
					$form .= '<li>';
						$form .= '<input type="radio" name="secupress-fix-current-admin-as-author" id="secupress-fix-current-admin-as-author_editor" value="editor" /> ';

						$form .= '<label for="secupress-fix-current-admin-as-author_editor">';
							/* translators: %s is a "More Info" symbol. */
							$form .= sprintf( __( 'Attribute all my Posts%s to:', 'secupress' ), $star1 );
						$form .= '</label> ';

						$form .= '<select name="secupress-fix-current-admin-as-author-editor-choose">';
							/* translators: %s is a user role name. */
							$form .= '<option value="-1">' . sprintf( __( '&mdash; Create new %s account &mdash;', 'secupress' ), $role_name_star ) . '</option>';

							// Existing Editors (or future Editors).
							$roles_can_publish = static::get_roles_that_can_publish_posts();

							if ( $roles_can_publish || $has_other_admin_authors ) {
								$users_can_publish = array();

								if ( $roles_can_publish ) {
									foreach ( $roles_can_publish as $role_can_publish => $label ) {
										$users_role_can_publish = get_users( array(
											'role' => $role_can_publish,
											'fields' => array( 'ID', 'user_login' )
										) );

										if ( $users_role_can_publish ) {
											$users_can_publish[] = array(
												'label' => $label,
												'users' => $users_role_can_publish,
											);
										}
									}
								}

								if ( $has_other_admin_authors ) {
									$users_can_publish[] = array(
										/* translators: %s is a user role name. */
										'label' => sprintf( __( 'Newly downgraded %s', 'secupress' ), strip_tags( $role_name_star ) ),
										'users' => $admins,
									);
								}

								if ( $users_can_publish ) {
									$only_one_role = count( $users_can_publish ) === 1;

									foreach ( $users_can_publish as $atts ) {
										if ( ! $only_one_role ) {
											$form .= '<optgroup label="' . esc_attr( $atts['label'] ) . '">';
										}
										foreach ( $atts['users'] as $i => $user ) {
											if ( is_string( $user ) ) {
												$form .= '<option value="' . $i . '">' . esc_html( $user ) . '</option>';
											} else {
												$form .= '<option value="' . (int) $user->ID . '">' . esc_html( $user->user_login ) . '</option>';
											}
										}
										if ( ! $only_one_role ) {
											$form .= '</optgroup>';
										}
									}
								}
							}

						$form .= '</select>';
					$form .= '</li>';

				$form .= '</ul>';

				/* translators: %s is a link to an online help. */
				$form .= sprintf( __( 'Having a hard time to make a choice? %s.', 'secupress' ), '<a href="' . SECUPRESS_WEB_VALID . 'admin-as-author/" target="_blank">' . __( 'Grab some help', 'secupress' ) . '</a>' ); ////

			$form .= '</fieldset>';
		}

		// Downgrade users.
		if ( $has_other_admin_authors ) {
			$admins = static::wrap_in_tag( $admins, 'strong' );

			$form  .= '<div class="secupress-group">';
				$form .= '<h4>' . ( $current_admin_is_author ? __( 'Other Administrators created Posts too', 'secupress' ) : __( 'Some Administrators created Posts', 'secupress' ) ) . '</h4>';
				$form  .= sprintf(
					/* translators: 1 is a user name (or a list of user names), 2 is a user role name. */
					_n( '%1$s\'s user role will be downgraded to %2$s.', '%1$s\'s user role will be downgraded to %2$s.', $count_admins, 'secupress' ),
					wp_sprintf_l( '%l', $admins ),
					$role_name_star
				);
			$form  .= '</div>';
		}

		$stars = array();

		if ( $current_admin_is_author ) {
			$stars[] = sprintf(
				__( '%1$s: %2$s', 'secupress' ),
				$star1,
				__( 'Only Posts will be attributed, not Pages or other post types.', 'secupress' )
			);
		}

		if ( $needs_new_role ) {
			$stars[] = sprintf(
				__( '%1$s: %2$s', 'secupress' ),
				$star2,
				sprintf( __( '"%s" is a new user role that will be created and used if needed.', 'secupress' ), $role_name )
			);
		}

		if ( $stars ) {
			$form .= '<div class="secupress-group">';
				$form .= '<span class="description">';
					$form .= implode( '<br/>', $stars );
				$form .= '</span>';
			$form  .= '</div>';
		}

		return $form;
	}


	/*
	 * Template part for step 1:
	 * - Ask login and email for the new Administrator account.
	 */
	protected static function get_fix_new_administrator_action_template_part( $current_admin_login ) {
		$form  = '<div class="secupress-group">';
			$form .= '<h4>' . sprintf( __( 'Create new %s account', 'secupress' ), _x( 'Administrator', 'User role' ) ) . '</h4>';

			$form .= '<label for="secupress-fix-current-admin-as-author-new-administrator-login">' . __( 'Username' ) . ' <span class="description">' . __( '(required)' ) . '</span></label><br/>';
			$form .= '<input type="text" id="secupress-fix-current-admin-as-author-new-administrator-login" name="secupress-fix-current-admin-as-author-new-administrator[login]" value="' . $current_admin_login . '-' . sanitize_title( _x( 'Administrator', 'User role' ), 'administrator' ) . '" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{1,60}" autocorrect="off" autocapitalize="off" title="' . esc_attr( sprintf( __( 'Allowed characters: %s.', 'secupress' ), static::allowed_characters_for_login() ) ) . '"/><br/>';

			$form .= '<label for="secupress-fix-current-admin-as-author-new-administrator-email">' . __( 'E-mail' ) . ' <span class="description">' . __( '(required)' ) . '</span></label><br/>';
			$form .= '<input type="email" id="secupress-fix-current-admin-as-author-new-administrator-email" name="secupress-fix-current-admin-as-author-new-administrator[email]" value="" required="required" aria-required="true"/><br/>';

			$form .= '<span class="description">' . __( 'A password reset link will be sent to you via email.', 'secupress' ) . '<br/>';
			$form .= __( 'Your current account will be downgraded only after you successfully log into your new Administrator account.', 'secupress' ) . '</span>';

		$form .= '</div>';

		return $form;
	}


	/*
	 * Template part for step 1:
	 * - Ask login and email for the new Editor account.
	 */
	protected static function get_fix_new_editor_action_template_part( $current_admin_login, $role_name ) {
		$form  = '<div class="secupress-group">';
			$form .= '<h4>' . sprintf( __( 'Create new %s account', 'secupress' ), $role_name ) . '</h4>';

			$form .= '<label for="secupress-fix-current-admin-as-author-new-editor-login">' . __( 'Username' ) . ' <span class="description">' . __( '(required)' ) . '</span></label><br/>';
			$form .= '<input type="text" id="secupress-fix-current-admin-as-author-new-editor-login" name="secupress-fix-current-admin-as-author-new-editor[login]" value="' . $current_admin_login . '-' . sanitize_title( $role_name, 'editor' ) . '" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{1,60}" autocorrect="off" autocapitalize="off" title="' . esc_attr( sprintf( __( 'Allowed characters: %s.', 'secupress' ), static::allowed_characters_for_login() ) ) . '"/><br/>';

			$form .= '<label for="secupress-fix-current-admin-as-author-new-editor-email">' . __( 'E-mail' ) . ' <span class="description">' . __( '(required)' ) . '</span></label><br/>';
			$form .= '<input type="email" id="secupress-fix-current-admin-as-author-new-editor-email" name="secupress-fix-current-admin-as-author-new-editor[email]" value="" required="required" aria-required="true"/><br/>';

			$form .= '<span class="description">' . __( 'A password reset link will be sent to you via email.', 'secupress' ) . '<br/>';
			$form .= __( 'This account data (biographical info, etc.) will be copied to the new account.', 'secupress' ) . '</span>';

		$form .= '</div>';

		return $form;
	}


	/*--------------------------------------------------------------------------------------------*/
	/* TOOLS FOR MONOSITE ======================================================================= */
	/*--------------------------------------------------------------------------------------------*/

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

			// We look for Posts with any status (except trash and auto-draft).
			$posts = get_posts( array(
				'author__in'  => array_keys( $users ),
				'post_status' => 'any',
			) );

			if ( $posts ) {
				$tmp = array();
				foreach ( $posts as $post ) {
					$post->post_author = (int) $post->post_author;

					if ( ! isset( $tmp[ $post->post_author ] ) ) {
						$tmp[ $post->post_author ] = 1;

						if ( $field ) {
							$users[ $post->post_author ] = $users[ $post->post_author ]->$field;
						}
					}
				}
				$out = array_intersect_key( $users, $tmp );
			}
		}

		return $out;
	}


	/*
	 * Make sure the given user ID corresponds to a valid Editor/Author.
	 *
	 * @since 1.0
	 *
	 * @param (int|object) $user_id User ID or object.
	 *
	 * @return (bool) Either the user is valid or not.
	 */
	final protected static function validate_editor( $user ) {
		$cap = post_type_exists( 'post' ) ? get_post_type_object( 'post' )->cap->publish_posts : 'publish_posts';
		return $user && user_can( $user, $cap );
	}


	final protected function attribute_posts_to( $editor, $check_if_valid = true ) {
		global $wpdb;

		$editor        = is_object( $editor ) ? $editor : get_userdata( $editor );
		$editor_id     = (int) $editor->ID;
		$current_admin = get_current_user_id();

		// Check if the user is valid.
		if ( $check_if_valid && ! static::validate_editor( $editor ) ) {
			return false;
		}

		// The user is valid: change Posts author.
		$post_ids = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM $wpdb->posts WHERE post_type = 'post' AND post_author = %d", $current_admin ) );

		if ( ! empty( $post_ids ) ) {
			$wpdb->update(
				$wpdb->posts,
				array( 'post_author' => $editor_id ),
				array( 'post_author' => $current_admin, 'post_type' => 'post' )
			);

			foreach ( $post_ids as $post_id ) {
				clean_post_cache( $post_id );
			}
		}

		// good: Posts attributed!
		// No $post_ids? Meh.
		$this->add_fix_message( 3, array( '<strong>' . $editor->user_login . '</strong>' ) );
		return true;
	}


	// Email login credentials to a newly-created user.

	final protected static function new_user_notification( $user ) {
		global $wpdb, $wp_hasher;

		$user = is_object( $user ) ? $user : get_userdata( $user );

		// The blogname option is escaped with esc_html on the way into the database in sanitize_option
		// we want to reverse this for the plain text arena of emails.
		$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

		// Generate something random for a password reset key.
		$key = wp_generate_password( 20, false );

		/** This action is documented in wp-login.php */
		do_action( 'retrieve_password_key', $user->user_login, $key );

		// Now insert the key, hashed, into the DB.
		if ( empty( $wp_hasher ) ) {
			require_once ABSPATH . WPINC . '/class-phpass.php';
			$wp_hasher = new PasswordHash( 8, true );
		}

		$hashed = time() . ':' . $wp_hasher->HashPassword( $key );

		$wpdb->update( $wpdb->users, array( 'user_activation_key' => $hashed ), array( 'user_login' => $user->user_login ) );

		$message  = sprintf( __( 'Username: %s' ), $user->user_login ) . "\r\n\r\n"; // WP i18n
		$message .= __( 'To set your password, visit the following address:', 'secupress' ) . "\r\n\r\n";
		$message .= '[' . network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user->user_login ), 'login' ) . "]\r\n\r\n";

		$message .= wp_login_url() . "\r\n";

		wp_mail( $user->user_email, sprintf( __( '[%s] Your username and password info', 'secupress' ), $blogname ), $message );
	}


	// After a fix, test if there are still Admins.

	final protected function final_test() {
		if ( $admins = static::get_admins( 'user_login' ) ) {
			// warning
			$this->add_fix_message( 100, array( static::wrap_in_tag( $admins, 'strong' ) ) );
		} else {
			// good
			$this->maybe_set_fix_status( 1 );
		}
	}


	/*--------------------------------------------------------------------------------------------*/
	/* MULTISITE ================================================================================ */
	/*--------------------------------------------------------------------------------------------*/

	protected function scan_multisite() {
		global $wpdb;

		$admins = static::get_usernames_per_blog();

		if ( $admins ) {
			$blog_names = array();

			foreach ( $admins as $blog_id => $users ) {
				$table_prefix = $wpdb->get_blog_prefix( $blog_id );
				$blog_name    = $wpdb->get_var( "SELECT option_value FROM {$table_prefix}options WHERE option_name = 'blogname' LIMIT 1" );
				$blog_names[] = '<strong>' . ( $blog_name ? esc_html( $blog_name ) : '(' . $blog_id . ')' ) . '</strong>';
			}

			// bad
			$this->add_message( 201, array( count( $blog_names ), $blog_names ) );
		} else {
			// good
			$this->add_message( 0 );
		}
	}


	/*--------------------------------------------------------------------------------------------*/
	/* TOOLS FOR MULTISITE ====================================================================== */
	/*--------------------------------------------------------------------------------------------*/

	/*
	 * Return a list of Administrators per blog + the number of their Posts like:
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

		$prefix  = $wpdb->esc_like( $wpdb->base_prefix );
		$results = $wpdb->get_results( "SELECT user_id, user_login, meta_key FROM $wpdb->usermeta AS um RIGHT JOIN $wpdb->users AS u ON um.user_id = u.ID WHERE meta_key LIKE '$prefix%capabilities' AND meta_value LIKE '%s:13:\"administrator\";b:1;%'" );

		if ( $results ) {
			// Fetch administrators.
			foreach ( $results as $result ) {
				$blog_id = preg_replace( "/^{$prefix}((?:\d+_|)*)capabilities$/", '$1', $result->meta_key );
				$blog_id = max( 1, (int) trim( $blog_id, '_' ) );
				$user_id = (int) $result->user_id;

				$user_logins[ $user_id ]     = isset( $user_logins[ $user_id ] ) ? $user_logins[ $user_id ] : esc_html( $result->user_login );
				$admins_per_blog[ $blog_id ] = isset( $admins_per_blog[ $blog_id ] ) ? $admins_per_blog[ $blog_id ] : array();
				$admins_per_blog[ $blog_id ][ $user_id ] = $user_id;
			}

			// Limit results to administrators that have created Posts.
			foreach ( $admins_per_blog as $blog_id => $user_ids ) {
				$table_prefix = $wpdb->get_blog_prefix( $blog_id );
				$user_ids     = implode( ',', $user_ids );
				$user_ids     = $wpdb->get_results( "SELECT post_author FROM {$table_prefix}posts WHERE post_author IN ($user_ids) AND post_type = 'post' AND post_status NOT IN ( 'trash', 'auto-draft' ) GROUP BY post_author" );

				if ( ! $user_ids ) {
					unset( $admins_per_blog[ $blog_id ] );
				} else {
					$admins_per_blog[ $blog_id ] = array();

					foreach ( $user_ids as $user ) {
						$admins_per_blog[ $blog_id ][ (int) $user->post_author ] = $user_logins[ (int) $user->post_author ];
					}
				}
			}
		}

		return $admins_per_blog;
	}


	protected function fix_network() {
		$admins = static::get_usernames_per_blog();

		if ( $admins ) {
			foreach ( $admins as $site_id => $data ) {
				$data = array( count( $data ), static::wrap_in_tag( $data, 'strong' ) );
				// Add a scan message for each listed sub-site.
				$this->add_subsite_message( 200, $data, 'scan', $site_id );
			}
			// cantfix
			$this->add_fix_message( 303 );
		} else {
			// Remove all previously stored messages for sub-sites.
			$this->set_empty_data_for_subsites();
			// good
			$this->add_fix_message( 0 );
		}
	}


	/*--------------------------------------------------------------------------------------------*/
	/* OTHER TOOLS ============================================================================== */
	/*--------------------------------------------------------------------------------------------*/

	/*
	 * Find the most appropriate role (the one with the largest number of capabilities, and able to publish Posts).
	 */
	final public static function get_new_role( $translated = false ) {
		static $new_role;
		static $role_name;

		if ( ! isset( $new_role ) ) {
			$new_role  = false;
			$role_name = false;
			$nbr_caps  = 0;
			$cap       = post_type_exists( 'post' ) ? get_post_type_object( 'post' )->cap->publish_posts : 'publish_posts';
			$roles     = wp_roles()->roles;
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
					$role_name = esc_html( translate_user_role( $roles[ $new_role ]['name'] ) );
				}
			}
		}

		return $translated ? $role_name : $new_role;
	}


	/*
	 * Find all user roles able to publish Posts.
	 */
	final protected static function get_roles_that_can_publish_posts() {
		static $roles_can;

		if ( ! isset( $roles_can ) ) {
			$roles_can = array();
			$cap       = post_type_exists( 'post' ) ? get_post_type_object( 'post' )->cap->publish_posts : 'publish_posts';
			$roles     = wp_roles()->roles;
			unset( $roles['administrator'] );

			if ( $roles ) {
				foreach ( $roles as $role => $details ) {
					if ( ! empty( $details['capabilities'][ $cap ] ) ) {
						$roles_can[ $role ] = translate_user_role( $details['name'] );
					}
				}
			}
		}

		return $roles_can;
	}


	/*
	 * Create a role able to create Posts.
	 */
	final public static function create_editor_role() {
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
			'moderate_comments'      => 1,
			'manage_categories'      => 1,
			'manage_links'           => 1,
			'upload_files'           => 1,
			'unfiltered_html'        => 1,
			'edit_posts'             => 1,
			'edit_others_posts'      => 1,
			'edit_published_posts'   => 1,
			'publish_posts'          => 1,
			'edit_pages'             => 1,
			'read'                   => 1,
			'level_7'                => 1,
			'level_6'                => 1,
			'level_5'                => 1,
			'level_4'                => 1,
			'level_3'                => 1,
			'level_2'                => 1,
			'level_1'                => 1,
			'level_0'                => 1,
			'edit_others_pages'      => 1,
			'edit_published_pages'   => 1,
			'publish_pages'          => 1,
			'delete_pages'           => 1,
			'delete_others_pages'    => 1,
			'delete_published_pages' => 1,
			'delete_posts'           => 1,
			'delete_others_posts'    => 1,
			'delete_published_posts' => 1,
			'delete_private_posts'   => 1,
			'edit_private_posts'     => 1,
			'read_private_posts'     => 1,
			'delete_private_pages'   => 1,
			'edit_private_pages'     => 1,
			'read_private_pages'     => 1,
		);

		add_role( $role, $role_name, $capabilities );

		$role_obj = get_role( $role );

		if ( ! $role_obj ) {
			return false;
		}

		return array( 'name' => $role, 'label' => $role_name );
	}


	/*
	 * Get the allowed characters for user login.
	 */
	final protected static function allowed_characters_for_login( $wrap = false ) {
		$allowed = array( 'A-Z', 'a-z', '0-9', '(space)', '_', '.', '-', '@', );
		$allowed = $wrap ? static::wrap_in_tag( $allowed ) : $allowed;
		$allowed = wp_sprintf_l( '%l', $allowed );

		return $allowed;
	}
}
