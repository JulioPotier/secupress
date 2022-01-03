<?php
/**
 * Module Name: Disallowed Logins
 * Description: Forbid some usernames to be used.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** EXISTING USERS WITH A BLACKLISTED USERNAME MUST CHANGE IT. ================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'auth_redirect', 'secupress_auth_redirect_blacklist_logins' );
/**
 * As soon as we are sure a user is connected, and before any redirection, check if the user login is not blacklisted.
 * If he is, he can't access the administration area and is asked to change it.
 *
 * @since 1.0
 *
 * @param (int) $user_id The user ID.
 */
function secupress_auth_redirect_blacklist_logins( $user_id ) {
	if ( ! is_admin() || defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		return;
	}

	$user = get_userdata( $user_id );
	$list = secupress_get_blacklisted_usernames();
	$list = array_flip( $list );

	if ( ! isset( $list[ $user->user_login ] ) ) {
		// Good, the login is not blacklisted.
		return;
	}

	$nonce_action = 'secupress-backlist-logins-new-login-' . $user_id;
	$error        = '';

	// A new login is submitted.
	if ( isset( $_POST['secupress-backlist-logins-new-login'] ) ) {

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			wp_die( __( 'Something went wrong.', 'secupress' ) );
		}

		if ( empty( $_POST['secupress-backlist-logins-new-login'] ) ) {
			// Empty username.
			$error = __( 'Username required', 'secupress' );
		} else {
			// Sanitize the submitted username.
			$user_login = sanitize_user( $_POST['secupress-backlist-logins-new-login'], true );

			if ( isset( $list[ $user_login ] ) ) {
				// The new login is blacklisted.
				$error = __( 'This username is also disallowed', 'secupress' );
			} else {
				// Good, change the user login.
				$inserted = secupress_blacklist_logins_change_user_login( $user_id, $user_login );

				if ( is_wp_error( $inserted ) ) {
					// Too bad, try again.
					$error = $inserted->get_error_message();
				} else {
					// Send the new login by email.
					secupress_blocklist_logins_new_user_notification( $user_id );

					// Kill session.
					wp_clear_auth_cookie();
					if ( function_exists( 'wp_destroy_current_session' ) ) { // WP 4.0 min.
						wp_destroy_current_session();
					}

					// Redirect the user to the login page.
					$login_url = wp_login_url( secupress_get_current_url( 'raw' ), true );
					$login_url = add_query_arg( 'secupress-relog', 1, $login_url );
					wp_redirect( esc_url_raw( $login_url ) );
					exit();
				}
			}
		}
	}

	// Allowed characters for the login.
	$allowed = esc_attr( secupress_blacklist_logins_allowed_characters() );

	// The form.
	ob_start();
	?>
	<form class="wrap" method="post">
		<h1><?php _e( 'Please change your username', 'secupress' ); ?></h1>
		<p>
			<?php
			printf(
				/** Translators: 1 is a user name, 2 is a link "to the site" */
				__( 'Your current username %1$s is disallowed. You will not be able to reach the administration area until you change your username. Meanwhile, you still have access %2$s.', 'secupress' ),
				'<strong>' . esc_html( $user->user_login ) . '</strong>',
				'<a href="' . esc_url( user_trailingslashit( home_url() ) ) . '">' . __( 'to the site', 'secupress' ) . '</a>'
			);
			?>
		</p>
		<?php echo $error ? '<p class="error">' . $error . '</p>' : ''; ?>
		<label for="new-login"><?php _e( 'New username:', 'secupress' ); ?></label><br/>
		<input type="text" id="new-login" name="secupress-backlist-logins-new-login" value="" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{2,60}" autocorrect="off" autocapitalize="off" title="<?php echo $allowed; ?>"/><br/>
		<input type="submit" />
		<?php wp_nonce_field( $nonce_action ) ?>
	</form>
	<?php
	$title   = __( 'Please change your username', 'secupress' );
	$content = ob_get_contents();
	ob_clean();

	secupress_action_page( $title, $content );
}


add_filter( 'wp_login_errors', 'secupress_blacklist_logins_display_login_message', 10, 2 );
/**
 * Display a message on the login form after the new login creation.
 *
 * @since 1.0
 *
 * @param (object) $errors      WP Error object.
 * @param (string) $redirect_to Redirect destination URL.
 *
 * @return (object) WP Error object.
 */
function secupress_blacklist_logins_display_login_message( $errors, $redirect_to ) {
	if ( empty( $_GET['secupress-relog'] ) ) {
		return $errors;
	}

	if ( empty( $errors ) ) {
		$errors = new WP_Error();
	}

	$errors->add( 'secupress_relog', __( 'You will receive your new login in your mailbox.', 'secupress' ), 'message' );

	return $errors;
}


/** --------------------------------------------------------------------------------------------- */
/** UTILITIES =================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Change a user login.
 *
 * @since 1.0
 *
 * @param (int)    $user_id    I let you guess what it is.
 * @param (string) $user_login Well...
 *
 * @return (int|object) User ID or WP_Error object on failure.
 */
function secupress_blacklist_logins_change_user_login( $user_id, $user_login ) {
	global $wpdb;

	// `user_login` must be between 1 and 60 characters.
	if ( empty( $user_login ) ) {
		return new WP_Error( 'empty_user_login', __( 'Cannot create a user with an empty login name.' ) );
	} elseif ( mb_strlen( $user_login ) > 60 ) {
		return new WP_Error( 'user_login_too_long', __( 'Username may not be longer than 60 characters.' ) );
	}

	if ( username_exists( $user_login ) ) {
		return new WP_Error( 'existing_user_login', __( 'Sorry, that username already exists!' ) );
	}

	$wpdb->update( $wpdb->users, array( 'user_login' => $user_login ), array( 'ID' => $user_id ) );

	wp_cache_delete( $user_id, 'users' );
	wp_cache_delete( $user_login, 'userlogins' );

	secupress_scanit( 'Bad_Usernames' );

	return $user_id;
}


/**
 * Send an email notification to a user with his/her login.
 *
 * @since 1.0
 *
 * @param (int|object) $user A user ID or a user object.
 */
function secupress_blocklist_logins_new_user_notification( $user ) {
	$user     = secupress_is_user( $user ) ? $user : get_userdata( $user );
	/* Translators: 1 is a blog name. */
	$subject  = sprintf( __( '[%s] Your username info', 'secupress' ), '###SITENAME###' );
	$message  = sprintf( __( 'Username: %s', 'secupress' ), $user->user_login ) . "\r\n\r\n";
	$message .= esc_url_raw( wp_login_url() ) . "\r\n";

	/**
	 * Filter the mail subject
	 * @param (string) $subject
	 * @param (WP_User) $user
	 * @since 2.2
	 */
	$subject = apply_filters( 'secupress.mail.blocklist_logins.subject', $subject, $user );
	/**
	 * Filter the mail message
	 * @param (string) $message
	 * @param (WP_User) $user
	 * @since 2.2
	 */
	$message = apply_filters( 'secupress.mail.blocklist_logins.message', $message, $user );

	secupress_send_mail( $user->user_email, $subject, $message );
}


/**
 * Tell if a username is blacklisted.
 *
 * @since 1.0
 *
 * @param (string) $username The username to test.
 *
 * @return (bool) true if blacklisted.
 */
function secupress_is_username_blacklisted( $username ) {
	$list = secupress_get_blacklisted_usernames();
	$list = array_flip( $list );
	return isset( $list[ mb_strtolower( $username ) ] );
}


/**
 * Logins blacklist: return the list of allowed characters for the usernames.
 *
 * @since 1.0
 *
 * @param (bool) $wrap If set to true, the characters will be wrapped with `code` tags.
 *
 * @return (string)
 */
function secupress_blacklist_logins_allowed_characters( $wrap = false ) {
	$allowed = is_multisite() ? array( 'a-z', '0-9' ) : array( 'A-Z', 'a-z', '0-9', '(space)', '_', '.', '-', '@' );
	if ( $wrap ) {
		foreach ( $allowed as $i => $char ) {
			$allowed[ $i ] = '<code>' . $char . '</code>';
		}
	}
	$allowed = wp_sprintf_l( '%l', $allowed );

	return sprintf( __( 'Allowed characters: %s.', 'secupress' ), $allowed );
}


/** --------------------------------------------------------------------------------------------- */
/** FORBID USER CREATION AND EDITION IF THE USERNAME IS BLACKLISTED. ============================ */
/** --------------------------------------------------------------------------------------------- */

/**
 * Launch the filters.
 */
if ( secupress_wp_version_is( '4.4-RC1-35773' ) ) :

	// `edit_user()`, `wpmu_validate_user_signup()`, `wp_insert_user()` and `register_new_user()`.
	add_filter( 'illegal_user_logins', 'secupress_blacklist_logins_illegal_user_logins' );

else :

	// `edit_user()`.
	add_action( 'user_profile_update_errors', 'secupress_blacklist_logins_user_profile_update_errors', 10, 3 );
	// `wpmu_validate_user_signup()`.
	add_filter( 'wpmu_validate_user_signup', 'secupress_blacklist_logins_wpmu_validate_user_signup' );
	// `wp_insert_user()`.
	add_filter( 'pre_user_login', 'secupress_blacklist_logins_pre_user_login' );
	// `register_new_user()`.
	add_filter( 'registration_errors', 'secupress_blacklist_logins_registration_errors', 10, 2 );

endif;


/**
 * Filter the blacklisted user names.
 * This filter is used in `wp_insert_user()`, `edit_user()` and `wpmu_validate_user_signup()`.
 *
 * @since 1.0
 *
 * @param (array) $usernames A list of forbidden user names.
 *
 * @return (array) The forbidden user names.
 */
function secupress_blacklist_logins_illegal_user_logins( $usernames ) {
	return array_merge( $usernames, secupress_get_blacklisted_usernames() );
}


/**
 * In `edit_user()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (object) $errors A WP_Error object, passed by reference.
 * @param (bool)   $update Whether this is a user update.
 * @param (object) $user   A WP_User object, passed by reference.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_user_profile_update_errors( $errors, $update, $user ) {
	if ( secupress_is_username_blacklisted( $user->user_login ) ) {
		$errors->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $errors;
}


/**
 * In `wpmu_validate_user_signup()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (array) $result An array containing the sanitized user name, the original one, the user email, and a `WP_Error` object.
 *
 * @return (array) The array with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_wpmu_validate_user_signup( $result ) {
	if ( secupress_is_username_blacklisted( $result['user_name'] ) ) {
		$result['errors']->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $result;
}


/**
 * In `wp_insert_user()`, detect forbidden logins.
 * If the username is in the blacklist, an empty username will be returned, triggering a `empty_user_login` error later.
 *
 * @since 1.0
 *
 * @param (string) $sanitized_user_login Current user login.
 *
 * @return (string) The user login or an empty string if blacklisted.
 */
function secupress_blacklist_logins_pre_user_login( $sanitized_user_login ) {
	if ( secupress_is_username_blacklisted( $sanitized_user_login ) ) {
		// Filter the `empty_user_login` error message.
		add_filter( 'gettext', 'secupress_blacklist_logins_gettext_filter', 8, 3 );
		return '';
	}
	return $sanitized_user_login;
}


/**
 * After a blacklisted username is detected, filter the `empty_user_login` error message.
 *
 * @since 1.0
 *
 * @param (string) $translations Translated text.
 * @param (string) $text Original text.
 * @param (string) $domain Text domain.
 *
 * @return (string) The translation.
 */
function secupress_blacklist_logins_gettext_filter( $translations, $text, $domain ) {
	if ( 'Cannot create a user with an empty login name.' === $text && 'default' === $domain ) {
		// No need to filter gettext anymore.
		remove_filter( 'gettext', 'secupress_blacklist_logins_gettext_filter', 8 );
		return __( 'Sorry, that username is not allowed.', 'secupress' );
	}
	return $translations;
}


/**
 * In `register_new_user()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (object) $errors               A WP_Error object containing any errors encountered during registration.
 * @param (string) $sanitized_user_login User's username after it has been sanitized.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_registration_errors( $errors, $sanitized_user_login ) {
	if ( secupress_is_username_blacklisted( $sanitized_user_login ) ) {
		$errors->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $errors;
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_logins_de_activate_file' );
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_logins_de_activate_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 */
function secupress_bad_logins_de_activate_file() {
	secupress_scanit( 'Bad_Usernames' );
}
